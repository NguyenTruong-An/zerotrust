"""Offline tooling/security regressions. No Docker mutations or real credentials.

The two MMDB fixture files are sparse placeholders; hashing is mocked ONLY for
those placeholders. These tests are not claimed as real GeoIP database tests.
"""
import copy
import datetime as dt
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock
from cryptography import x509
from cryptography.hazmat.primitives.serialization import Encoding
import risk_promotion as r

NOW=dt.datetime(2026,11,11,17,tzinfo=dt.timezone.utc)


class FakeDocker:
    def __init__(self,m,root,app,jvm):
        self.m=m;self.root=root;self.app=app;self.jvm=jvm;self.rows=[];self.queries=[]
        self.images={i:{'Id':i,'Os':'linux','Architecture':'amd64'} for i in (r.OLD,r.NEW)}
        self.ledger='661092940\t1';self.current_head=m['source']['review_HEAD'];self.changes=[]
        self.nets=copy.deepcopy(m['networks'])
        for service,w in m['baseline_runtime'].items():
            host={'PortBindings':copy.deepcopy(w['ports']),'ReadonlyRootfs':w['readonly_rootfs'],'Privileged':w['privileged']}
            for dest,key in [('CapAdd','cap_add'),('CapDrop','cap_drop'),('SecurityOpt','security_opt'),('RestartPolicy','restart'),('Memory','memory'),
                             ('Tmpfs','tmpfs'),('Binds','binds'),('Devices','devices'),('NetworkMode','network_mode')]:host[dest]=copy.deepcopy(w[key])
            self.rows.append({'Id':w['id'],'Image':w['image'],'Name':'/'+r.PROJECT+'-'+service+'-1',
                'Config':{'Labels':{'com.docker.compose.project':r.PROJECT,'io.zerotrust.scope':r.PROJECT,'com.docker.compose.service':service},
                    'Env':[],'User':w['user'],'Entrypoint':copy.deepcopy(w['entrypoint']),'Cmd':copy.deepcopy(w['cmd'])},
                'HostConfig':host,'Mounts':copy.deepcopy(w['mounts']),'NetworkSettings':{'Networks':{n:{'Aliases':[service]} for n in w['networks']}},
                'State':{'Running':True,'Health':{'Status':'healthy'}}})

    def local(self):self.queries.append('local')
    def containers(self):self.queries.append('inspect');return self.rows
    def image(self,i):self.queries.append('image');return self.images[i]
    def networks(self,names):self.queries.append('networks');return list(self.nets.values())
    def read_config(self,name,file):
        self.queries.append('cp:'+file)
        if file=='application.properties':return self.app
        if file=='jvm.args':return self.jvm
        if file in ('ca.crt','server.crt'):
            key='ca' if file=='ca.crt' else 'leaf';return (self.root/self.m['tls'][key]['path']).read_bytes()
        return x509.load_pem_x509_crl((self.root/self.m['tls']['crl']['path']).read_bytes()).public_bytes(Encoding.DER)
    def v5(self):self.queries.append('select-v5');return self.ledger
    def head(self):self.queries.append('git-head');return self.current_head
    def build_input_changes(self,old,new):self.queries.append('git-diff');return self.changes


class PromotionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.base=json.loads(r.DEFAULT_MANIFEST.read_text());cls.schema=json.loads((r.HERE/'risk-promotion.schema.json').read_text())
        cls.root=Path(tempfile.mkdtemp(prefix='tooling-fixture-',dir=r.ROOT/(r.PREFIX+'phase22'))).resolve()
        assert cls.root.is_relative_to((r.ROOT/(r.PREFIX+'phase22')).resolve())
        for rec in cls.base['receipts']+[cls.base['config']['artifact_defaults'],*cls.base['tls'].values()]+[cls.base['source']]:
            target=cls.root/rec['path'];target.parent.mkdir(parents=True,exist_ok=True);target.write_bytes((r.ROOT/rec['path']).read_bytes())
        for e,rec in cls.base['geoip']['files'].items():
            p=cls.root/cls.base['geoip']['directory']/(e+'.mmdb');p.parent.mkdir(parents=True,exist_ok=True)
            with p.open('wb') as f:f.truncate(rec['bytes'])
        cls.original_sha=staticmethod(r.sha_file)
        cls.app=('server.ssl.enabled=true\nspring.datasource.url=jdbc:mysql://mysql:3306/pd_staging_risk?sslMode=VERIFY_IDENTITY\n'
            'risk.policy.network-risk.enabled=true\nrisk.policy.network-risk.trusted-cidrs=198.51.100.0/25\n'
            'risk.policy.network-risk.high-risk-cidrs=203.0.113.0/24,10.253.245.27/32\n').encode()
        cls.jvm=b'-Dcom.sun.net.ssl.checkRevocation=true\n-Dcom.sun.security.enableCRLDP=true\n'

    def setUp(self):
        self.m=copy.deepcopy(self.base)
        for w in self.m['baseline_runtime'].values():w['environment_sha256']=r.sha(b'[]')
        self.m['config']['application_sha256']=r.sha(self.app);self.m['config']['jvm_sha256']=r.sha(self.jvm)
        self.m['rollback'].update(runtime=copy.deepcopy(self.m['baseline_runtime']['risk']),application_sha256=r.sha(self.app),jvm_sha256=r.sha(self.jvm))
        self.a=FakeDocker(self.m,self.root,self.app,self.jvm)
        self.digests={self.root/self.m['geoip']['directory']/(e+'.mmdb'):v['sha256'] for e,v in self.m['geoip']['files'].items()}
        self.hash_patch=mock.patch.object(r,'sha_file',side_effect=lambda p:self.digests[p] if p in self.digests else self.original_sha(p))
        self.hash_patch.start();self.addCleanup(self.hash_patch.stop)

    def validate(self,**kwargs):
        return r.inspect_manifest(self.m,self.root,self.a,NOW,schema=self.schema,**kwargs)

    def rejected(self,code=None,**kwargs):
        with self.assertRaises(r.Rejected) as cm:self.validate(**kwargs)
        if code:self.assertIn(code,str(cm.exception))

    def test_valid_manifest_read_only(self):
        before={p:r.sha(p.read_bytes()) for p in self.root.rglob('*') if p.is_file() and p.suffix!='.mmdb'}
        self.assertEqual(self.validate()['status'],'PASS')
        after={p:r.sha(p.read_bytes()) for p in self.root.rglob('*') if p.is_file() and p.suffix!='.mmdb'}
        self.assertEqual(before,after)
        self.assertTrue(all(x in ('local','inspect','image','networks','git-head','git-diff','select-v5') or x.startswith('cp:') for x in self.a.queries))

    def test_unknown_schema_field(self):self.m['unreviewed']=True;self.rejected('SCHEMA_EXTRA_FIELD')
    def test_schema_missing_field(self):del self.m['rollback'];self.rejected('SCHEMA_REQUIRED')
    def test_wrong_project(self):self.m['project']='protected-legacy';self.rejected('SCHEMA_CONST')
    def test_wrong_manifest_image(self):self.m['images']['proposed']=r.OLD;self.rejected('SCHEMA_CONST')
    def test_image_identity_mismatch(self):self.a.images[r.NEW]['Id']=r.OLD;self.rejected('IMAGE_MISMATCH')
    def test_image_platform(self):self.a.images[r.NEW]['Architecture']='arm64';self.rejected('IMAGE_PLATFORM')
    def test_owner_label(self):self.a.rows[0]['Config']['Labels']['io.zerotrust.scope']='other';self.rejected('OWNERSHIP_MISMATCH')
    def test_unhealthy_runtime(self):self.a.rows[0]['State']['Health']['Status']='unhealthy';self.rejected('ACTIVE_STACK_NOT_HEALTHY')
    def test_missing_service(self):self.a.rows.pop();self.rejected('MISSING_OWNED_SERVICE')
    def test_config_drift(self):self.a.app+=b'changed=true\n';self.rejected('ACTIVE_CONFIG_DRIFT')
    def test_source_head_drift(self):self.a.current_head='a'*40;self.rejected('HEAD_DRIFT')
    def test_git_option_injection_blocked_before_command(self):
        with mock.patch.object(r.subprocess,'run') as call:
            with self.assertRaisesRegex(r.Rejected,'GIT_REVISION_NOT_EXACT_COMMIT'):
                r.ReadOnlyDocker().build_input_changes('--output=not-created','a'*40)
            call.assert_not_called()
    def test_manifest_build_commit_pinned(self):self.m['source']['build_HEAD']='--output=not-created';self.rejected('SOURCE_COMMIT_IDENTITY')
    def test_source_file_drift(self):self.digests[self.root/r.SOURCE]='0'*64;self.rejected('SOURCE_DRIFT')
    def test_changed_build_inputs(self):self.a.changes=['risk-scoring-service/pom.xml'];self.rejected('COMMITTED_BUILD_INPUT_DRIFT')
    def test_base_receipt_drift(self):
        p=self.root/self.m['receipts'][0]['path'];old=p.read_bytes();p.write_bytes(b'changed')
        try:self.rejected('BASE_RECEIPT_DRIFT')
        finally:p.write_bytes(old)
    def test_missing_dataset(self):
        path=next(iter(self.digests));old=Path.is_file
        with mock.patch.object(Path,'is_file',lambda p:False if p==path else old(p)):self.rejected('MISSING_GEOIP_DATASET')
    def test_corrupt_dataset(self):self.digests[next(iter(self.digests))]='0'*64;self.rejected('CORRUPT_GEOIP_DATASET')
    def test_stale_dataset(self):
        with self.assertRaisesRegex(r.Rejected,'STALE_OR_FUTURE_GEOIP'):
            r.inspect_manifest(self.m,self.root,self.a,NOW+dt.timedelta(days=32),schema=self.schema)
    def test_missing_crl_flags(self):
        self.a.jvm=b'-Dcom.sun.net.ssl.checkRevocation=false';self.m['config']['jvm_sha256']=r.sha(self.a.jvm)
        self.rejected('TLS_REVOCATION_REQUIRED')
    def test_missing_tls_verify(self):
        self.a.app=self.app.replace(b'VERIFY_IDENTITY',b'DISABLED');self.m['config']['application_sha256']=r.sha(self.a.app)
        self.rejected('TLS_VERIFICATION_REQUIRED')
    def test_expired_tls_crl(self):
        v=self.m['tls']
        with self.assertRaisesRegex(r.Rejected,'TLS_CRL_EXPIRED'):
            r.tls_validate(*[(self.root/v[k]['path']).read_bytes() for k in ('ca','leaf','crl')],NOW+dt.timedelta(days=8))
    def test_expired_leaf(self):
        v=self.m['tls']
        with self.assertRaisesRegex(r.Rejected,'TLS_CERT_EXPIRED'):
            r.tls_validate(*[(self.root/v[k]['path']).read_bytes() for k in ('ca','leaf','crl')],NOW+dt.timedelta(days=40))
    def test_b0_change_rejected(self):self.m['policy']['weights']['network']='0.5';self.rejected('SCHEMA_CONST')
    def test_actual_b0_config_change(self):
        self.a.app+=b'risk.policy.model=EXPERIMENTAL_B1\n';self.m['config']['application_sha256']=r.sha(self.a.app)
        self.rejected('B0_OR_NETWORK_POLICY_DRIFT')
    def test_v5_mismatch(self):self.a.ledger='123\t1';self.rejected('INCOMPATIBLE_V5')
    def test_country_policy_not_approved(self):self.m['policy']['lists']['trusted-country-codes']=['VN'];self.rejected('SCHEMA_CONST')
    def test_mount_write(self):self.m['override']['mount']['read_only']=False;self.rejected('SCHEMA_CONST')
    def test_unsafe_dataset_path(self):self.m['geoip']['directory']='../protected';self.rejected('UNSAFE_PROPOSED_MOUNT')
    def test_network_drift(self):self.a.nets[r.PROJECT+'_core']['Internal']=False;self.rejected('NETWORK_DEFINITION_DRIFT')
    def test_published_risk_port(self):
        row=next(x for x in self.a.rows if x['Name'].endswith('-risk-1'));row['HostConfig']['PortBindings']={'8443/tcp':[{'HostIp':'0.0.0.0','HostPort':'8443'}]};self.rejected('RUNTIME_CONFIG')
    def test_foreign_mount(self):self.a.rows[0]['Mounts'][0]['Name']='legacy-data';self.rejected('RUNTIME_CONFIG')
    def test_conflicting_writer(self):
        other=copy.deepcopy(next(x for x in self.a.rows if x['Name'].endswith('-risk-1')))
        other['Id']='f'*64;other['Config']['Labels']={};other['Name']='/foreign-risk';self.a.rows.append(other)
        self.rejected('CONFLICTING_RISK_WRITERS')
    def test_conflicting_writer_without_alias_or_labels(self):
        other=copy.deepcopy(next(x for x in self.a.rows if x['Name'].endswith('-risk-1')))
        other.update(Id='f'*64,Image=r.NEW,Name='/unnamed-writer');other['Config']['Labels']={}
        other['NetworkSettings']['Networks'][r.PROJECT+'_core']['Aliases']=[];self.a.rows.append(other)
        self.rejected('CONFLICTING_RISK_WRITERS')
        with self.assertRaisesRegex(r.Rejected,'CONFLICTING_RISK_WRITERS'):r.assert_legacy_runtime(self.root,self.a)
    def test_rollback_wrong_image(self):self.m['rollback']['image']=r.NEW;self.rejected('UNVERIFIED_ROLLBACK')
    def test_rollback_config_not_verified(self):self.m['rollback']['jvm_sha256']='0'*64;self.rejected('UNVERIFIED_ROLLBACK')
    def test_rollback_database_restore_forbidden(self):self.m['rollback']['restore_database']=True;self.rejected('UNVERIFIED_ROLLBACK')
    def test_future_plans_preserve_security_state(self):
        d=r.future_design(self.m)
        self.assertFalse(d['execution_enabled']);self.assertFalse(d['rollback']['restore_database'])
        self.assertIn('pending operations',d['rollback']['preserve_current'])
        self.assertEqual(d['backup-only']['ready'],'DESIGN_ONLY')
    def test_execution_not_authorized_by_manifest(self):self.m['approval_status']='APPROVED';self.rejected('SCHEMA_CONST')
    def test_normal_operation_baseline_allowed(self):r.assert_legacy_runtime(self.root,self.a)
    def test_normal_restart_promoted_image_blocked(self):
        next(x for x in self.a.rows if x['Name'].endswith('-risk-1'))['Image']=r.NEW
        with self.assertRaisesRegex(r.Rejected,'LEGACY_OPERATION_BLOCKED'):r.assert_legacy_runtime(self.root,self.a)
    def test_normal_restart_stopped_unrecorded_candidate_blocked(self):
        other=copy.deepcopy(next(x for x in self.a.rows if x['Name'].endswith('-risk-1')))
        other.update(Id='f'*64,Image=r.NEW,Name='/stopped-partial-cutover');other['State']['Running']=False;self.a.rows.append(other)
        with self.assertRaisesRegex(r.Rejected,'RECOVERY_REQUIRED'):r.assert_legacy_runtime(self.root,self.a)
    def test_normal_restart_promoted_marker_blocked(self):
        p=self.root/r.ACTIVE_MARKER;p.parent.mkdir(parents=True,exist_ok=True);p.write_text('{}')
        try:
            with self.assertRaisesRegex(r.Rejected,'PROMOTED_PROFILE'):r.assert_legacy_runtime(self.root,self.a)
        finally:p.unlink()
    def test_operate_guard_runs_before_compose_or_receipt_writes(self):
        import operate
        with mock.patch.object(r,'assert_legacy_runtime',side_effect=r.Rejected('PROMOTED_PROFILE')),mock.patch.object(operate,'run') as run:
            with self.assertRaisesRegex(r.Rejected,'PROMOTED_PROFILE'):operate.configure()
            run.assert_not_called()
    def test_read_only_command_adapter_rejects_mutation(self):
        with mock.patch.object(r.subprocess,'run') as call:
            with self.assertRaisesRegex(r.Rejected,'COMMAND_FORBIDDEN'):r.ReadOnlyDocker().command('docker','stop','not-executed')
            call.assert_not_called()
    def test_duplicate_json_key(self):
        with self.assertRaisesRegex(r.Rejected,'DUPLICATE_JSON_KEY'):r.json_bytes(b'{"project":"one","project":"two"}')
    def test_absolute_and_traversal_paths(self):
        for value in ('../outside','C:/private','/private','x/../../private'):
            with self.subTest(value=value),self.assertRaises(r.Rejected):r.local_path(self.root,value)


if __name__=='__main__':unittest.main(verbosity=2)
