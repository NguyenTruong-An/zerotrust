"""Canonical JSON and pre-cutover/recovery boundaries. Fake Docker, no active state."""
import contextlib
import contextvars
import copy
import json
import hashlib
import hmac
from pathlib import Path
import tempfile
import types
import unittest
from unittest import mock
import network_v2_contract as c
import network_v2_rollout as n


def fixture(role):
    mounts=[{'Type':'volume','Name':n.PROJECT+'_'+role+'-config','Source':'/vol/'+role,
             'Destination':'/run/demo' if role=='risk' else '/run/secrets','RW':False}]
    if role=='risk':mounts+=[{'Type':'bind','Name':None,'Source':'/data/geo','Destination':'/geoip','RW':False}]
    entry=['java'] if role=='risk' else ['kc.sh']
    base={'Id':'baseline-'+role,'Name':'/'+role,'Image':n.OLD[role],'Mounts':mounts,
          'State':{'Running':True,'Status':'running'},'NetworkSettings':{'Networks':{n.CORE:{'Aliases':[role]}}},
          'Config':{'Env':['JAVA_HOME=/tools','EXACT=value']+(['SPRING_APPLICATION_JSON={"geo":true}'] if role=='risk' else []),
                    'Entrypoint':entry,'Cmd':None if role=='risk' else ['start'],'User':'10001:10001' if role=='risk' else '65532:65532',
                    'Labels':{},'WorkingDir':'/app','Healthcheck':None if role=='risk' else {'Test':['CMD','bash','/run/secrets/ready.sh']}},
          'HostConfig':{'Memory':1024**3,'ReadonlyRootfs':False,'Privileged':False,'PortBindings':{},'CapDrop':['ALL'],
                        'CapAdd':None,'SecurityOpt':['no-new-privileges'],'RestartPolicy':{'Name':'unless-stopped','MaximumRetryCount':0},
                        'Binds':None,'Devices':[],'NetworkMode':n.CORE,'PidMode':'','UTSMode':'','IpcMode':'private','CgroupnsMode':'private'}}
    image={'Id':n.NEW[role],'Os':'linux','Architecture':'amd64','Config':{'Env':['JAVA_HOME=/tools'],'Entrypoint':entry,'Cmd':None,
            'WorkingDir':'/app','Labels':{'source':'candidate'},'Volumes':None,'Healthcheck':None}}
    m={'release':{'new_images':n.NEW,'risk_override':{'z':{'b':2,'a':1},'mode':'SHADOW','retention':False},'keycloak_cmd':['start','--optimized']}}
    return base,image,m


class CanonicalEnvironmentTests(unittest.TestCase):
    def test_nested_key_order_and_whitespace_identical(self):
        a=['A=exact','SPRING_APPLICATION_JSON={"z":{"b":2,"a":1},"a":false}']
        b=['SPRING_APPLICATION_JSON= { "a":false,"z":{"a":1,"b":2} }','A=exact']
        self.assertEqual(c.environment_hash(a),c.environment_hash(b))
    def test_canonical_round_trip_through_manifest(self):
        base,image,m=fixture('risk');first=c.expected_spec('risk',base,image,m,n.PROJECT,n.CORE)
        m=json.loads(c.canonical_json(m));second=c.expected_spec('risk',base,image,m,n.PROJECT,n.CORE)
        self.assertEqual(first['env'],second['env']);self.assertEqual(first['contract'],second['contract'])
    def test_invalid_JSON_rejected(self):
        for value in ('{','null','[]','{"x":NaN}','{"x":Infinity}','{"x":1e309}'):
            with self.subTest(value=value),self.assertRaises(n.r.Rejected):c.environment_hash(['SPRING_APPLICATION_JSON='+value])
    def test_duplicate_JSON_keys_rejected(self):
        with self.assertRaisesRegex(n.r.Rejected,'DUPLICATE_JSON_KEY'):c.environment_hash(['SPRING_APPLICATION_JSON={"x":1,"x":2}'])
    def test_duplicate_environment_keys_rejected(self):
        with self.assertRaisesRegex(n.r.Rejected,'DUPLICATE'):c.environment_hash(['A=1','A=2'])
    def test_changed_extra_missing_or_non_JSON_values_change_hash(self):
        baseline=c.environment_hash(['A=1','B=exact','SPRING_APPLICATION_JSON={"mode":"SHADOW"}'])
        for env in (['A=2','B=exact','SPRING_APPLICATION_JSON={"mode":"SHADOW"}'],['A=1','B=exact','EXTRA=1','SPRING_APPLICATION_JSON={"mode":"SHADOW"}'],
                    ['A=1','SPRING_APPLICATION_JSON={"mode":"SHADOW"}'],['A=1','B=exact','SPRING_APPLICATION_JSON={"mode":"ENFORCED"}']):
            self.assertNotEqual(baseline,c.environment_hash(env))
    def test_boolean_and_number_not_silently_equated(self):
        self.assertNotEqual(c.environment_hash(['SPRING_APPLICATION_JSON={"retention":false}']),c.environment_hash(['SPRING_APPLICATION_JSON={"retention":0}']))
    def test_newline_empty_key_and_invalid_ENV_rejected(self):
        for value in ('A=x\ny','=1','NO_EQUALS'):
            with self.subTest(value=value),self.assertRaises(n.r.Rejected):c.normalized_environment([value])


class CandidateContractTests(unittest.TestCase):
    def test_both_roles_actual_projection_match_full_contract(self):
        for role in n.NEW:
            with self.subTest(role=role):
                base,image,m=fixture(role);spec=c.expected_spec(role,base,image,m,n.PROJECT,n.CORE)
                c.verify_contract(spec['projected'],spec['contract'])
    def test_expected_env_and_create_args_share_same_serialization(self):
        for role in n.NEW:
            base,image,m=fixture(role);spec=c.expected_spec(role,base,image,m,n.PROJECT,n.CORE)
            args=c.create_args(spec,'candidate','a'*32,'digest',n.PROJECT,n.CORE,'private.env','C:/geo')
            self.assertNotIn('--entrypoint',args);self.assertNotIn('--publish',args);self.assertIn(n.NEW[role],args)
            self.assertEqual(spec['env'],c.normalized_environment(spec['env']))
            self.assertEqual(args[-len(spec['cmd']):],spec['cmd']) if spec['cmd'] else None
    def test_image_entrypoint_default_command_env_and_volume_drift_rejected(self):
        changes=[('Entrypoint',['unexpected']),('Cmd',['unexpected']),('Env',['JAVA_HOME=/tools','UNEXPECTED=true']),('Volumes',{'/unexpected':{}})]
        for key,value in changes:
            base,image,m=fixture('risk');image['Config'][key]=value
            with self.subTest(key=key),self.assertRaises(n.r.Rejected):c.expected_spec('risk',base,image,m,n.PROJECT,n.CORE)
    def test_image_pin_or_platform_drift_rejected(self):
        for key,value in [('Id','wrong'),('Os','windows'),('Architecture','arm64')]:
            base,image,m=fixture('risk');image[key]=value
            with self.subTest(key=key),self.assertRaises(n.r.Rejected):c.expected_spec('risk',base,image,m,n.PROJECT,n.CORE)
    def test_actual_environment_entrypoint_command_and_security_mismatch_rejected(self):
        base,image,m=fixture('risk');spec=c.expected_spec('risk',base,image,m,n.PROJECT,n.CORE)
        changes=[('Config','Env',['JAVA_HOME=/bad']),('Config','Entrypoint',['bad']),('Config','Cmd',['bad']),
                 ('Config','User','0:0'),('HostConfig','ReadonlyRootfs',False),('HostConfig','Privileged',True),
                 ('HostConfig','CapAdd',['SYS_ADMIN']),('HostConfig','Memory',1),('HostConfig','SecurityOpt',[]),
                 ('HostConfig','Devices',[{'PathOnHost':'/dev/test'}]),('HostConfig','PidMode','host')]
        for section,key,value in changes:
            row=copy.deepcopy(spec['projected']);row[section][key]=value
            with self.subTest(key=key),self.assertRaisesRegex(n.r.Rejected,'CONFIGURATION_DRIFT'):c.verify_contract(row,spec['contract'])
    def test_mount_network_port_and_extra_label_drift_rejected(self):
        base,image,m=fixture('risk');spec=c.expected_spec('risk',base,image,m,n.PROJECT,n.CORE)
        for mutate in (lambda r:r['Mounts'][0].update(RW=True),lambda r:r['Mounts'][0].update(Source='/wrong'),
                       lambda r:r['NetworkSettings'].update(Networks={'foreign':{}}),lambda r:r['HostConfig'].update(PortBindings={'8443/tcp':[{'HostIp':'0.0.0.0','HostPort':'443'}]}),
                       lambda r:r['Config']['Labels'].update(unexpected='true')):
            row=copy.deepcopy(spec['projected']);mutate(row)
            with self.assertRaises(n.r.Rejected):c.verify_contract(row,spec['contract'])


class CoordinatorTests(unittest.TestCase):
    def setUp(self):
        self.c=object.__new__(n.Context);self.c.m={'services':{s:{'name':s} for s in n.SERVICES}}
        self.c.grant=contextvars.ContextVar('RAM_V3',default=False);self.c.selection=None;self.c.recovery_schema_allowed=False;self.c.digest='digest'
        self.c.old=mock.Mock();self.c.old.module.ProjectLock=contextlib.nullcontext
        self.c.executor=mock.Mock();self.c.authorize=mock.Mock(return_value={'checkpoint':'c'*32,'recover_target':None})
        self.c.initialize=mock.Mock();self.c.validate=mock.Mock();self.c.candidate_preflight=mock.Mock();self.c.schema=mock.Mock(return_value=7)
        self.c.pre_cutover_unchanged=mock.Mock(return_value=True)
        self.j={'id':'a'*32,'operation':'apply','stage':'AUTHORIZED','before':{'mode':'BASELINE','risk':'risk','keycloak':'keycloak'},
                'running_before':dict.fromkeys(n.SERVICES,True),'request':{'checkpoint':'c'*32}}
        self.c.executor.new_operation.return_value=self.j
        self.c.executor.stage.side_effect=lambda j,stage,**fields:j.update(stage=stage,**fields)
    def test_offline_preflight_failure_before_private_journal_or_any_active_mutation(self):
        self.c.candidate_preflight.side_effect=n.r.Rejected('CONFIG_DRIFT')
        with self.assertRaisesRegex(n.r.Rejected,'CONFIG_DRIFT'):self.c.execute({},'apply')
        self.c.initialize.assert_not_called();self.c.executor.new_operation.assert_not_called();self.c.executor.d.stop.assert_not_called()
    def test_preflight_rechecked_under_shared_lock_before_initialization(self):
        self.c.candidate_preflight.side_effect=[{},n.r.Rejected('DRIFT_UNDER_LOCK')]
        with self.assertRaisesRegex(n.r.Rejected,'DRIFT_UNDER_LOCK'):self.c.execute({},'apply')
        self.c.initialize.assert_not_called();self.c.executor.d.raw.assert_not_called()
    def test_actual_invalid_candidate_rejected_before_quiesce_DDL_or_stop(self):
        self.c.create_role=mock.Mock(side_effect=n.r.Rejected('CANDIDATE_FULL_CONFIGURATION_DRIFT'))
        self.c.quiesce=mock.Mock();self.c.migrate=mock.Mock()
        with self.assertRaises(n.r.Rejected):self.c.execute({},'apply')
        self.c.quiesce.assert_not_called();self.c.migrate.assert_not_called();self.c.executor.d.stop.assert_not_called()
        self.c.executor.finish.assert_called_once();self.assertEqual(self.c.executor.finish.call_args.kwargs['result'],'REJECTED_BEFORE_CUTOVER')
        self.assertFalse(self.c.grant.get())
    def test_both_actual_candidates_checked_before_stop_and_V7_noop(self):
        order=[];self.c.create_role=mock.Mock(side_effect=lambda j,role:(order.append('create-'+role),role)[1])
        self.c.executor.d.inspect.side_effect=lambda name:{'State':{'Running':False,'Status':'created'}}
        self.c.verify_replacement=mock.Mock(side_effect=lambda *args:order.append('verify'))
        self.c.quiesce=mock.Mock(side_effect=lambda j:(order.append('quiesce'),j.update(active_mutation_started=True)))
        self.c.migrate=mock.Mock(side_effect=lambda j:order.append('V7-noop'));self.c.switch=mock.Mock(return_value={'mode':'SHADOW'})
        self.c.execute({},'apply')
        self.assertEqual(order,['create-keycloak','create-risk','verify','verify','quiesce','V7-noop'])
    def test_failure_after_quiesce_requires_recovery_and_never_finishes_journal(self):
        self.c.create_role=mock.Mock(return_value='candidate');self.c.verify_replacement=mock.Mock()
        self.c.executor.d.inspect.return_value={'State':{'Running':False,'Status':'created'}}
        self.c.quiesce=mock.Mock(side_effect=lambda j:j.update(active_mutation_started=True))
        self.c.migrate=mock.Mock(side_effect=n.r.Rejected('AFTER_MUTATION_FAILURE'))
        with self.assertRaises(n.r.Rejected):self.c.execute({},'apply')
        self.c.executor.finish.assert_not_called();self.c.executor.d.stop.assert_called_once_with('ingress')
        self.assertEqual(self.j['stage'],'FAILED_CLOSED_RECOVERY_REQUIRED')
    def test_V7_migration_is_metadata_noop_no_Flyway_or_SQL_write(self):
        self.c.grant.set(True);self.c.migrate(self.j)
        self.c.executor.d.raw.assert_not_called();self.c.executor.stage.assert_called_once_with(self.j,'MIGRATION_NO_OP_VALIDATED_V7')
    def test_V5_or_partial_schema_rejected_no_DDL(self):
        self.c.grant.set(True)
        for version in (5,6):
            self.c.schema.return_value=version
            with self.assertRaises(n.r.Rejected):self.c.migrate(self.j)
        self.c.executor.d.raw.assert_not_called()
    def test_recovery_uses_current_storage_and_same_baseline_on_V7(self):
        self.c.grant.set(True);target={**self.j,'manifest':self.c.digest,'status':'RUNNING','operation':'apply'}
        self.c.module=mock.Mock();self.c.module.sealed_read.return_value=target;self.c.executor.d.rows.return_value=[]
        self.c.quiesce=mock.Mock();self.c.resume=mock.Mock()
        j={'id':'b'*32,'request':{'recover_of':self.j['id'],'recover_target':'BASELINE'}}
        self.c.recover(j)
        self.c.resume.assert_called_once_with(target,target['before']);self.c.executor.restore_verify.assert_not_called();self.c.executor.d.raw.assert_not_called()
        self.assertTrue(j['active_mutation_started'])
    def test_rollback_keeps_CURRENT_storage_and_exact_old_pair(self):
        self.j['before']['mode']='SHADOW';self.c.quiesce=mock.Mock();self.c.switch=mock.Mock();self.c.initial_state=mock.Mock(return_value={'mode':'BASELINE','risk':'old-risk','keycloak':'old-kc'})
        self.c.execute({},'rollback')
        selected=self.c.switch.call_args.args[1];self.assertEqual((selected['risk'],selected['keycloak']),('old-risk','old-kc'))
        self.c.executor.restore_verify.assert_not_called();self.c.executor.d.raw.assert_not_called()


class QuiescenceTests(unittest.TestCase):
    def setUp(self):
        self.c=object.__new__(n.Context);self.c.m={'services':{s:{'name':s} for s in n.SERVICES}};self.c.digest='digest'
        self.c.require_grant=mock.Mock();self.c.executor=mock.Mock();self.c.executor.name.side_effect=lambda role:role
        self.c.executor.d.owned.side_effect=lambda name:{'State':{'Running':True}}
        self.row={'Name':'/risk','Id':'risk-id','Image':n.OLD['risk'],'Config':{'Labels':{}},'State':{'Running':True},'NetworkSettings':{'Networks':{n.CORE:{'Aliases':['risk']}}}}
    def test_invalid_stopped_candidate_is_never_a_stop_target_or_ownership_exception(self):
        stopped=copy.deepcopy(self.row);stopped.update(Name='/old-invalid',Id='old');stopped['State']['Running']=False
        stopped['Config']['Labels']={'io.zerotrust.role':'risk','io.zerotrust.shadow.manifest':self.c.digest}
        self.c.executor.d.rows.return_value=[self.row,stopped]
        self.c.quiesce({'id':'a'*32},True)
        self.assertNotIn(mock.call('old-invalid'),self.c.executor.d.owned.call_args_list)
        self.assertNotIn(mock.call('old-invalid'),self.c.executor.d.stop.call_args_list)
    def test_duplicate_writer_rejected_before_any_stop(self):
        other=copy.deepcopy(self.row);other.update(Id='second',Name='/second-risk')
        self.c.executor.d.rows.return_value=[self.row,other]
        with self.assertRaisesRegex(n.r.Rejected,'DUPLICATE_RISK_WRITER'):self.c.quiesce({},True)
        self.c.executor.d.stop.assert_not_called();self.c.executor.stage.assert_not_called()
    def test_ownership_failure_precedes_first_stop(self):
        self.c.executor.d.rows.return_value=[self.row];self.c.executor.d.owned.side_effect=n.r.Rejected('FOREIGN')
        with self.assertRaisesRegex(n.r.Rejected,'FOREIGN'):self.c.quiesce({},True)
        self.c.executor.d.stop.assert_not_called();self.c.executor.stage.assert_not_called()


class SafeStagingRejectionTests(unittest.TestCase):
    def setUp(self):
        self.c=object.__new__(n.Context);self.c.executor=mock.Mock();self.c.digest='digest'
        self.c.executor.name.side_effect=lambda role:role
        self.before={'mode':'BASELINE','risk':'baseline-risk','keycloak':'baseline-kc'}
        self.c.executor.state.return_value=self.before
        self.c.executor.d.owned.return_value={'State':{'Running':True}}
        self.j={'id':'a'*32,'before':self.before,'running_before':dict.fromkeys(n.SERVICES,True),
                'risk_id':'exact','risk_name':'staged-risk'}
        self.row={'Id':'exact','Name':'/staged-risk','Image':n.NEW['risk'],'State':{'Running':False,'Status':'created'},
                  'Config':{'Labels':{'io.zerotrust.operation':self.j['id'],'io.zerotrust.scope':n.PROJECT,
                                     'io.zerotrust.shadow.manifest':self.c.digest,'io.zerotrust.role':'risk'}}}
        self.c.executor.d.rows.return_value=[self.row]
    def test_rejected_stopped_owned_candidate_is_safe_without_any_actions(self):
        self.assertTrue(self.c.pre_cutover_unchanged(self.j));self.c.executor.d.stop.assert_not_called();self.c.executor.d.start.assert_not_called()
    def test_running_or_foreign_or_unknown_candidate_never_terminally_hidden(self):
        for change in (lambda r:r['State'].update(Running=True),lambda r:r.update(Id='foreign'),
                       lambda r:r['Config']['Labels'].update({'io.zerotrust.scope':'foreign'})):
            saved=copy.deepcopy(self.row);change(self.row);self.assertFalse(self.c.pre_cutover_unchanged(self.j));self.row.clear();self.row.update(saved)
    def test_changed_baseline_running_state_is_not_safe_rejection(self):
        self.c.executor.d.owned.return_value={'State':{'Running':False}}
        self.assertFalse(self.c.pre_cutover_unchanged(self.j))
    def test_durable_selection_changed_is_not_safe_rejection(self):
        self.c.executor.state.return_value={**self.before,'mode':'SHADOW'}
        self.assertFalse(self.c.pre_cutover_unchanged(self.j))
    def test_active_mutation_flag_always_requires_recovery(self):
        self.j['active_mutation_started']=True;self.assertFalse(self.c.pre_cutover_unchanged(self.j))


class HistoricalBindingTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup);self.root=Path(self.tmp.name)
        self.m={'services':{'risk':{'name':'same-risk'},'keycloak':{'name':'same-kc'}},'predecessors':{}}
        self.roots={};self.documents={}
        for version,digest,packet in [('v1',n.PREVIOUS_SHA,n.PREVIOUS_PACKET_SHA),('v2',n.PARENT_SHA,n.PARENT_PACKET_SHA)]:
            private=self.root/version;private.mkdir();(private/'journal').mkdir();(private/'state.key').write_bytes(b'K'*32)
            self.roots[digest]=private;self.write(private/'state.json',{'manifest':digest,'mode':'BASELINE','risk':'same-risk','keycloak':'same-kc'})
            self.write(private/'journal/closed.json',{'status':'DONE'})
            self.m['predecessors'][digest]={'packet_sha256':packet,'control_files_sha256':{}}
        for constant,name,digest in [('PREVIOUS_DESCRIPTOR','d1',n.PREVIOUS_SHA),('PREVIOUS_PACKET','p1',n.PREVIOUS_PACKET_SHA),
                                     ('PARENT_DESCRIPTOR','d2',n.PARENT_SHA),('PARENT_PACKET','p2',n.PARENT_PACKET_SHA)]:
            path=self.root/name;self.documents[path]=digest
            patcher=mock.patch.object(n,constant,path);patcher.start();self.addCleanup(patcher.stop)
        for name,value in [('PREVIOUS_PRIVATE',self.roots[n.PREVIOUS_SHA]),('PARENT_PRIVATE',self.roots[n.PARENT_SHA])]:
            patcher=mock.patch.object(n,name,value);patcher.start();self.addCleanup(patcher.stop)
        for patcher in (mock.patch.object(n.r,'ROOT',self.root),mock.patch.object(n.r,'sha_file',side_effect=lambda p:self.documents[p] if p in self.documents else hashlib.sha256(p.read_bytes()).hexdigest())):
            patcher.start();self.addCleanup(patcher.stop)
        self.refresh()
    def write(self,path,body):path.write_bytes(n.canonical({'body':body,'mac':hmac.digest(b'K'*32,n.canonical(body),'sha256').hex()}))
    def refresh(self):
        for digest,private in self.roots.items():
            self.m['predecessors'][digest]['control_files_sha256']={str(p.relative_to(self.root)).replace('\\','/'):hashlib.sha256(p.read_bytes()).hexdigest() for p in private.rglob('*') if p.is_file()}
    def test_v1_and_v2_closed_and_MAC_verified_without_writes(self):
        before=copy.deepcopy(self.m);n.predecessor_guard(self.m);self.assertEqual(before,self.m)
    def test_either_history_change_rejected(self):
        path=self.roots[n.PARENT_SHA]/'journal/closed.json';path.write_bytes(path.read_bytes()+b' ')
        with self.assertRaisesRegex(n.r.Rejected,'STATE_OR_JOURNAL_DRIFT'):n.predecessor_guard(self.m)
    def test_v2_new_unfinished_operation_rejected(self):
        self.write(self.roots[n.PARENT_SHA]/'journal/new.json',{'status':'RUNNING'});self.refresh()
        with self.assertRaisesRegex(n.r.Rejected,'OPERATION_PENDING'):n.predecessor_guard(self.m)
    def test_public_hash_cannot_replace_MAC_integrity(self):
        path=self.roots[n.PARENT_SHA]/'state.json';value=json.loads(path.read_bytes());value['mac']='0'*64;path.write_bytes(n.canonical(value));self.refresh()
        with self.assertRaisesRegex(n.r.Rejected,'MAC_INVALID'):n.predecessor_guard(self.m)
    def test_unexpected_predecessor_cannot_be_injected(self):
        self.m['predecessors']['foreign']={}
        with self.assertRaisesRegex(n.r.Rejected,'PREDECESSOR_SET'):n.predecessor_guard(self.m)


class SigningBindingTests(unittest.TestCase):
    def test_fixed_v3_namespace_never_overwrites_v1_v2(self):
        self.assertEqual(str(n.ANCHOR).replace('\\','/'),(Path.home()/'.zerotrust-owner/network-v2-shadow-v3/anchor.json').as_posix())
        self.assertNotIn(n.PRIVATE,(n.PREVIOUS_PRIVATE,n.PARENT_PRIVATE))
    def test_old_signature_rejected_for_new_binding(self):
        from test_network_v2_rollout import AuthorizationTests
        fixture=AuthorizationTests('test_valid_backup_RAM_only');fixture.setUp()
        with self.assertRaisesRegex(n.r.Rejected,'REQUEST_BINDING'):
            n.verify(fixture.envelope(),fixture.m,'V3_DESCRIPTOR','V3_PACKET','backup-only',set(),fixture.anchor,now=1100)


class BoundPreflightTests(unittest.TestCase):
    def setUp(self):
        self.c=object.__new__(n.Context);self.c.executor=mock.Mock();self.c.schema=mock.Mock(return_value=7)
        self.c.m={'release':{'candidate_contracts':{role:{'exact':role} for role in n.NEW}}}
        self.c.candidate_spec=mock.Mock(side_effect=lambda role:{'contract':{'exact':role}})
    def test_bound_preflight_is_read_only_and_checks_both_roles(self):
        self.assertEqual(self.c.candidate_preflight()['status'],'PASS')
        self.assertEqual(self.c.candidate_spec.call_count,2)
        self.c.executor.d.raw.assert_not_called();self.c.executor.stage.assert_not_called()
    def test_bound_contract_drift_rejected_without_any_actions(self):
        self.c.m['release']['candidate_contracts']['risk']={'exact':'tampered'}
        with self.assertRaisesRegex(n.r.Rejected,'BOUND_CANDIDATE_CONTRACT_DRIFT'):self.c.candidate_preflight()
        self.c.executor.d.stop.assert_not_called();self.c.executor.d.raw.assert_not_called()
    def test_wrong_schema_rejected_before_candidate_creation_or_migration(self):
        self.c.schema.return_value=5
        with self.assertRaisesRegex(n.r.Rejected,'VALIDATED_V7'):self.c.candidate_preflight()
        self.c.candidate_spec.assert_not_called();self.c.executor.d.raw.assert_not_called()


if __name__=='__main__':unittest.main()
