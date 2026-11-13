"""Changed binding only: RAM test signer, fake Docker/state; never creates an owner grant or runtime."""
import base64,contextvars,copy,time,types,unittest
from unittest import mock
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding,PublicFormat
import network_v2_rollout as n

class AuthorizationTests(unittest.TestCase):
    def setUp(self):
        self.m={'owner_sid':'TEST_OWNER','release':{'old_images':n.OLD,'new_images':n.NEW,'shadow':n.SHADOW},
                'checkpoint_rules':{'maximum_age_seconds':1800,'independent_restore_required':True,'automatic_database_restore':False}}
        self.signer=Ed25519PrivateKey.generate();pub=self.signer.public_key().public_bytes(Encoding.Raw,PublicFormat.Raw)
        self.anchor={'kind':'OWNER_CONTROLLED_NETWORK_V2_SHADOW_ONLY','project':n.PROJECT,'owner_sid':'TEST_OWNER','issuer':n.ISSUER,
                     'descriptor_sha256':'a'*64,'packet_sha256':'b'*64,'operations':list(n.OPERATIONS),'expires':2000,
                     'public_key':base64.b64encode(pub).decode(),'public_key_sha256':n.sha(pub)}
        self.p={'id':'c'*32,'project':n.PROJECT,'operation':'backup-only','descriptor_sha256':'a'*64,'packet_sha256':'b'*64,
                'release_sha256':n.sha(n.canonical(self.m['release'])),'checkpoint_rules_sha256':n.sha(n.canonical(self.m['checkpoint_rules'])),
                'maintenance':list(n.WRITERS),'checkpoint':None,'recover_of':None,'recover_target':None,
                'issued':1000,'expires':1500,'owner_sid':'TEST_OWNER','issuer':n.ISSUER}
    def envelope(self):return {'payload':self.p,'signature':base64.b64encode(self.signer.sign(n.canonical(self.p))).decode()}
    def verify(self,operation='backup-only',used=(),envelope=None):return n.verify(envelope or self.envelope(),self.m,'a'*64,'b'*64,operation,set(used),self.anchor,now=1100)
    def test_valid_backup_RAM_only(self):self.assertEqual(self.verify()['operation'],'backup-only')
    def test_old_Risk_only_anchor_cannot_authorize(self):
        self.anchor['kind']='OWNER_CONTROLLED_ACTIVE_ONLY'
        with self.assertRaisesRegex(n.r.Rejected,'ANCHOR_SCOPE'):self.verify()
    def test_old_issuer_cannot_authorize(self):
        self.p['issuer']='OWNER_EXPLICIT_ACTIVE_AUTHORIZATION'
        with self.assertRaisesRegex(n.r.Rejected,'BINDING'):self.verify()
    def test_both_image_pins_are_signed(self):
        for role in ('risk','keycloak'):
            with self.subTest(role=role):
                m=copy.deepcopy(self.m);m['release']['new_images']={**n.NEW,role:n.OLD[role]}
                with self.assertRaisesRegex(n.r.Rejected,'BINDING'):n.verify(self.envelope(),m,'a'*64,'b'*64,'backup-only',set(),self.anchor,now=1100)
    def test_signature_tampering(self):
        envelope=self.envelope();envelope['payload']['expires']=1501
        with self.assertRaisesRegex(n.r.Rejected,'SIGNATURE'):self.verify(envelope=envelope)
    def test_expired_request(self):
        self.p['expires']=1099
        with self.assertRaisesRegex(n.r.Rejected,'EXPIRED'):self.verify()
    def test_request_TTL_cannot_exceed_ten_minutes(self):
        self.p['expires']=1601
        with self.assertRaisesRegex(n.r.Rejected,'EXPIRED'):self.verify()
    def test_anchor_expiry(self):
        self.anchor['expires']=1099
        with self.assertRaisesRegex(n.r.Rejected,'ANCHOR_EXPIRED'):self.verify()
    def test_replay(self):
        with self.assertRaisesRegex(n.r.Rejected,'ALREADY_USED'):self.verify(used=[self.p['id']])
    def test_unknown_force_flag_rejected(self):
        self.p['force']=True
        with self.assertRaisesRegex(n.r.Rejected,'SHAPE'):self.verify()
    def test_checkpoint_required_for_apply_and_restore(self):
        for operation in ('apply','restore-verify'):
            self.p['operation']=operation
            with self.assertRaisesRegex(n.r.Rejected,'CHECKPOINT_REQUIRED'):self.verify(operation)
            self.p['checkpoint']='d'*32;self.assertEqual(self.verify(operation)['checkpoint'],'d'*32);self.p['checkpoint']=None
    def test_backup_scope_cannot_apply(self):
        self.p.update(operation='apply',checkpoint='d'*32);self.anchor['operations']=['backup-only','restore-verify']
        with self.assertRaisesRegex(n.r.Rejected,'ANCHOR_EXPIRED_OR_OPERATION'):self.verify('apply')
    def test_exact_operation_maintenance_and_descriptor(self):
        for field,value in [('operation','restart'),('maintenance',['risk']),('descriptor_sha256','0'*64),('packet_sha256','0'*64),('project','foreign')]:
            original=self.p[field];self.p[field]=value
            with self.subTest(field=field),self.assertRaisesRegex(n.r.Rejected,'BINDING'):self.verify()
            self.p[field]=original
    def test_recovery_requires_exact_target_and_reference(self):
        self.p['operation']='recover'
        with self.assertRaisesRegex(n.r.Rejected,'RECOVERY_BINDING'):self.verify('recover')
        self.p.update(recover_of='d'*32,recover_target='BASELINE');self.assertEqual(self.verify('recover')['recover_target'],'BASELINE')
    def test_baseline_recovery_also_requires_rollback_scope(self):
        self.p.update(operation='recover',recover_of='d'*32,recover_target='BASELINE');self.anchor['operations']=['recover']
        with self.assertRaisesRegex(n.r.Rejected,'ROLLBACK_SCOPE'):self.verify('recover')

class MigrationTests(unittest.TestCase):
    def test_fixed_anchor_cannot_be_selected_by_HOME_or_cli(self):
        self.assertEqual(str(n.ANCHOR).replace('\\','/'),(Path.home()/'.zerotrust-owner/network-v2-shadow-v2/anchor.json').as_posix())
    def ledger(self,versions):return '\n'.join(v+'\t'+str(n.CHECKSUMS[v])+'\t1' for v in versions)
    def test_V5_and_V7_supported(self):
        self.assertEqual(n.schema_state(self.ledger('12345')),5);self.assertEqual(n.schema_state(self.ledger('1234567')),7)
    def test_V5_checksum_immutable(self):
        with self.assertRaisesRegex(n.r.Rejected,'CHECKSUM'):n.schema_state(self.ledger('12345').replace('661092940','661092941'))
    def test_unknown_or_failed_migration_not_a_success(self):
        with self.assertRaises(n.r.Rejected):n.schema_state(self.ledger('1234567')+'\n8\t1\t1')
        with self.assertRaises(n.r.Rejected):n.schema_state(self.ledger('1234567').replace('7\t-601621005\t1','7\t-601621005\t0'))
    def test_partial_V6_is_never_treated_as_ready_V7(self):
        self.assertEqual(n.schema_state(self.ledger('123456')),6)
    def test_failed_DDL_only_tolerated_for_scoped_baseline_recovery(self):
        text=self.ledger('12345')+'\n6\t1392077360\t0'
        with self.assertRaises(n.r.Rejected):n.schema_state(text)
        self.assertEqual(n.schema_state(text,allow_partial=True),6)
    def test_duplicate_writers_never_admitted_even_during_recovery(self):
        for role in ('risk','keycloak'):
            with self.subTest(role=role),self.assertRaisesRegex(n.r.Rejected,'DUPLICATE'):n.admit_writers(['old','new'],'old',True,role)
    def test_wrong_running_selection_rejected(self):
        with self.assertRaisesRegex(n.r.Rejected,'SELECTION_MISMATCH'):n.admit_writers(['new'],'old',False,'risk')
        n.admit_writers(['old'],'old',False,'risk');n.admit_writers([],'old',False,'risk')
    def test_only_known_partial_transition_can_have_uncommitted_selection(self):n.admit_writers(['new'],'old',True,'risk')

class CoordinatorTests(unittest.TestCase):
    def setUp(self):
        self.c=object.__new__(n.Context);self.c.m={'services':{s:{'name':s} for s in n.SERVICES}}
        self.c.grant=contextvars.ContextVar('TEST_RAM_GRANT',default=False);self.c.selection=None;self.c.recovery_schema_allowed=False
        self.c.executor=mock.Mock();self.c.executor.state.return_value={'mode':'BASELINE','risk':'old-risk','keycloak':'old-keycloak'}
        self.c.executor.d.owned.return_value={'State':{'Running':False}}
        self.c.executor.d.rows.return_value=[]
        self.c.old=mock.Mock();self.c.old.module.ProjectLock.return_value=contextlib_for_test()
        self.c.authorize=mock.Mock(return_value={'recover_target':None});self.c.initialize=mock.Mock();self.c.validate=mock.Mock()
        self.c.schema=mock.Mock(return_value=5)
        self.c.verify_runtime=mock.Mock(return_value={'status':'PASS'});self.c.digest='a'*64
        self.j={'id':'b'*32,'operation':'apply','stage':'AUTHORIZED','request':{'checkpoint':'c'*32},
                'running_before':dict.fromkeys(n.SERVICES,True),'before':{'mode':'BASELINE','risk':'old-risk','keycloak':'old-keycloak'}}
        self.c.executor.new_operation.return_value=self.j
    def test_unsigned_admission_happens_before_private_and_lock(self):
        self.c.authorize.side_effect=n.r.Rejected('NO_SIGNATURE')
        with self.assertRaisesRegex(n.r.Rejected,'NO_SIGNATURE'):self.c.execute(None,'apply')
        self.c.initialize.assert_not_called();self.c.old.module.ProjectLock.assert_not_called()
    def test_stale_checkpoint_before_admission_never_stops_ingress(self):
        self.c.authorize.return_value={'checkpoint':'c'*32,'recover_target':None}
        self.c.executor.load_checkpoint.side_effect=n.r.Rejected('STALE')
        with self.assertRaisesRegex(n.r.Rejected,'STALE'):self.c.execute({},'apply')
        self.c.executor.d.stop.assert_not_called();self.c.initialize.assert_not_called()
    def test_apply_migrates_before_creating_both_roles(self):
        self.c.authorize.return_value={'checkpoint':'c'*32,'recover_target':None}
        events=[];self.c.quiesce=mock.Mock(side_effect=lambda *a:events.append('quiesce'))
        self.c.migrate=mock.Mock(side_effect=lambda *a:events.append('migrate'))
        self.c.create_role=mock.Mock(side_effect=lambda j,role:(events.append(role),'new-'+role)[1])
        self.c.switch=mock.Mock(return_value={'mode':'SHADOW'})
        self.assertEqual(self.c.execute({},'apply')['mode'],'SHADOW')
        self.assertEqual(events,['quiesce','migrate','keycloak','risk']);self.assertFalse(self.c.grant.get())
    def test_freshness_rechecked_after_quiescence_before_DDL(self):
        self.c.authorize.return_value={'checkpoint':'c'*32,'recover_target':None};self.c.quiesce=mock.Mock(side_effect=lambda j:j.update(stage='QUIESCED'))
        self.c.executor.load_checkpoint.side_effect=[{}, {},n.r.Rejected('STALE_AFTER_QUIESCE')]
        self.c.migrate=mock.Mock()
        with self.assertRaisesRegex(n.r.Rejected,'STALE_AFTER'):self.c.execute({},'apply')
        self.c.migrate.assert_not_called();self.c.executor.d.stop.assert_called_with('ingress')
    def test_internal_failure_cannot_commit_or_open_ingress(self):
        self.c.grant.set(True) # RAM test capability, never an actual authorization/anchor.
        self.c.executor.d.owned.return_value={'State':{'Running':False}}
        self.c.verify_runtime.side_effect=n.r.Rejected('DECLARED_INTERNAL_FAILURE')
        j={'running_before':dict.fromkeys(n.SERVICES,False),'stage':'QUIESCED'}
        with self.assertRaisesRegex(n.r.Rejected,'INTERNAL_FAILURE'):self.c.resume(j,{'mode':'SHADOW','risk':'new-risk','keycloak':'new-keycloak'})
        self.c.executor.save_state.assert_not_called();self.c.executor.d.start.assert_not_called();self.assertIsNone(self.c.selection)
    def test_rollback_uses_current_storage_and_old_pair_not_restore(self):
        self.j.update(operation='rollback',before={'mode':'SHADOW','risk':'new-risk','keycloak':'new-keycloak'})
        self.c.quiesce=mock.Mock();self.c.switch=mock.Mock()
        self.c.initial_state=mock.Mock(return_value={'mode':'BASELINE','risk':'old-risk','keycloak':'old-keycloak'})
        self.c.execute({},'rollback');selected=self.c.switch.call_args.args[1]
        self.assertEqual((selected['risk'],selected['keycloak']),('old-risk','old-keycloak'))
        self.c.executor.restore_verify.assert_not_called();self.c.executor.load_checkpoint.assert_not_called()
    def test_restart_uses_durable_selection_without_migration(self):
        self.j['before']={'mode':'SHADOW','risk':'new-risk','keycloak':'new-keycloak'};self.c.quiesce=mock.Mock();self.c.switch=mock.Mock();self.c.migrate=mock.Mock()
        self.c.execute({},'restart');self.assertEqual(self.c.switch.call_args.args[1],self.j['before']);self.c.migrate.assert_not_called()
    def test_restart_after_STOPPED_recovery_restores_saved_running_intent(self):
        saved=dict.fromkeys(n.SERVICES,True)
        self.j['before']={'mode':'SHADOW','risk':'new-risk','keycloak':'new-keycloak','running_intent':saved}
        self.j['running_before']={service:service in ('mysql','crl') for service in n.SERVICES}
        self.c.quiesce=mock.Mock();self.c.switch=mock.Mock()
        self.c.execute({},'restart');self.assertEqual(self.j['running_before'],saved)
    def test_backup_admission_requires_healthy_baseline_before_private_creation(self):
        self.c.validate.side_effect=n.r.Rejected('UNHEALTHY')
        with self.assertRaisesRegex(n.r.Rejected,'UNHEALTHY'):self.c.execute({},'backup-only')
        self.c.validate.assert_called_with(True);self.c.initialize.assert_not_called();self.c.executor.d.stop.assert_not_called()
    def test_already_V7_migration_is_noop(self):
        self.c.grant.set(True);self.c.schema.return_value=7
        self.c.migrate(self.j);self.c.executor.d.raw.assert_not_called();self.c.executor.table_witness.assert_not_called()
    def test_partial_V6_rejected_before_migrator_run(self):
        self.c.grant.set(True);self.c.schema.return_value=6
        with self.assertRaisesRegex(n.r.Rejected,'PARTIAL_SCHEMA'):self.c.migrate(self.j)
        self.c.executor.d.raw.assert_not_called()
    def test_creator_preserves_multi_argument_image_entrypoint(self):
        self.c.grant.set(True);self.c.module=mock.Mock();self.c.m.update(geoip={'directory':'target/network-v2-integration-20261112'},
            release={'risk_override':dict(n.SHADOW),'keycloak_cmd':['--config-file=/run/secrets/keycloak.conf','start','--optimized','--log-level=info,org.keycloak.events:error']})
        self.c.executor.d.rows.return_value=[];self.c.executor.d.raw.return_value=b'new-id'
        self.c.verify_replacement=mock.Mock()
        for role,entry in [('risk',['java','@/run/demo/jvm.args','-jar','/app/application.jar','--spring.config.additional-location=file:/run/demo/application.properties']),('keycloak',['/opt/keycloak/bin/kc.sh'])]:
            self.c.executor.d.owned.return_value={'Config':{'Env':['TEST_ONLY=public'],'Entrypoint':entry,'Cmd':None,'Healthcheck':{'Test':['CMD','bash','/run/secrets/ready.sh']}},'HostConfig':{'Memory':1024**3}}
            self.c.executor.d.image.return_value={'Config':{'Entrypoint':entry}}
            self.c.create_role(self.j,role);args=self.c.executor.d.raw.call_args.args
            self.assertNotIn('--entrypoint',args);self.assertIn(n.NEW[role],args)
            if role=='keycloak':self.assertEqual(args[-4:],tuple(self.c.m['release']['keycloak_cmd']))
    def test_ingress_quiesced_before_both_role_variants_and_redis(self):
        self.c.grant.set(True);self.c.executor.name.side_effect=lambda service:service
        self.c.executor.d.rows.return_value=[{'Name':'/risk','Config':{'Labels':{}}},{'Name':'/keycloak','Config':{'Labels':{}}},
            {'Name':'/new-risk','Config':{'Labels':{'io.zerotrust.shadow.manifest':self.c.digest,'io.zerotrust.role':'risk'}}},
            {'Name':'/new-keycloak','Config':{'Labels':{'io.zerotrust.shadow.manifest':self.c.digest,'io.zerotrust.role':'keycloak'}}}]
        self.c.quiesce(self.j,True)
        stops=[call.args[0] for call in self.c.executor.d.stop.call_args_list]
        self.assertEqual(stops,['ingress','gateway','frontend','backend','risk','new-risk','keycloak','new-keycloak','redis'])
    def test_no_private_stage_or_helper_without_grant(self):
        with self.assertRaisesRegex(n.r.Rejected,'WITHOUT_NEW_OWNER_SIGNATURE'):self.c.create_role(self.j,'risk')
        self.c.executor.d.raw.assert_not_called()

def contextlib_for_test():
    from contextlib import nullcontext
    return nullcontext()

if __name__=='__main__':unittest.main()
