import copy,datetime,json,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
from executor import Blocked,Checkpoint,Executor,LIVE,REHEARSAL,canonical,sha
class ExecutorSecurityTests(unittest.TestCase):
    def test_migrator_hash_helper_is_read_only_and_scoped(self):
        from executor import migrate_config_hashes
        with patch('executor.run',return_value=b'abc  /in/migration.properties\ndef  /in/jvm.args\n012  /in/trust.p12\n') as command:
            with self.assertRaisesRegex(Blocked,'MIGRATOR_CONFIG_SCOPE'):migrate_config_hashes('protected-legacy-backup','pin')
            command.assert_not_called()
            self.assertEqual(len(migrate_config_hashes(LIVE+'_migrate-config','pin')),3)
            args=command.call_args.args
            self.assertIn('--read-only',args);self.assertIn('none',args)
            # Only read/search DAC bypass is restored; the mount stays read-only.
            self.assertEqual(args[args.index('--cap-add')+1],'DAC_READ_SEARCH');self.assertEqual(args.count('--cap-add'),1)
            self.assertIn('/in/migration.properties',args)
            self.assertIn('type=volume,source='+LIVE+'_migrate-config,target=/in,readonly',args)
    def test_acceptance_and_archive_helpers_have_distinct_owned_names(self):
        from operation import helper
        e=object.__new__(Executor);e.project=REHEARSAL;e.id='a'*16
        e.plan={'core_network':'private-core','tooling_image':'bound-tooling'}
        with patch('operation.run') as command:
            name=helper(e,Path('public'),Path('results'))
            self.assertEqual(name,e.name('acceptance-helper'))
            self.assertNotEqual(name,e.name('helper'))
            args=command.call_args.args
            self.assertEqual(args[args.index('--name')+1],name)
            self.assertNotIn('--publish',args)
    def test_hold_cli_requires_go_before_any_mutation(self):
        import rollout
        with patch('rollout.run') as command,patch('packet.validate'),patch('pathlib.Path.read_text',return_value=json.dumps(self.plan())):
            with self.assertRaisesRegex(Blocked,'EXPLICIT_OWNER_GO_REQUIRED'):rollout.hold(None)
            command.assert_not_called()
    def test_restore_canonicalization_preserves_data_and_real_charset_changes(self):
        from restore_worker import canonical_sql
        source=b'  `name` varchar(9) COLLATE utf8mb4_unicode_ci NOT NULL,\n'
        explicit=b'  `name` varchar(9) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci NOT NULL,\n'
        self.assertEqual(canonical_sql(source),canonical_sql(explicit))
        self.assertNotEqual(canonical_sql(source),canonical_sql(explicit.replace(b'utf8mb4',b'latin1')))
        data=b"INSERT INTO `data` VALUES ('CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci');\n"
        self.assertEqual(canonical_sql(data),data)
        self.assertEqual(canonical_sql(b'  `flag` tinyint DEFAULT NULL,\n'),b'  `flag` tinyint,\n')
        self.assertEqual(canonical_sql(b'  `flag` tinyint NOT NULL DEFAULT 0,\n'),b'  `flag` tinyint NOT NULL DEFAULT 0,\n')
    def plan(self):return {'project':LIVE,'run_id':'a'*16,'output':'target/d10-phase3-unit-test','approval_nonce':'fresh-nonce','source':{},'candidate_images':{},'pending_count':2}
    def approval(self,p):return {'type':'D10_EXPLICIT_OWNER_GO','plan_sha256':sha(canonical(p)),'nonce':p['approval_nonce'],'owner_message_sha256':'owner-message-hash','expires_utc':(datetime.datetime.now(datetime.timezone.utc)+datetime.timedelta(hours=1)).isoformat(),**{k:True for k in ('controlled_deployment','maintenance','force_fresh_login','temporary_fail_closed','designated_test_accounts','preserve_existing_pending')}}
    def test_no_live_command_before_explicit_go(self):
        with patch('executor.run') as command:
            with self.assertRaisesRegex(Blocked,'EXPLICIT_OWNER_GO_REQUIRED'):Executor(self.plan(),'live')
            command.assert_not_called()
    def test_api_redirect_never_forwards_a_bearer(self):
        import http.server,threading,urllib.request,urllib.error
        from native_admin import NoRedirect
        received=[]
        class Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self,*args):pass
            def do_GET(self):
                if self.path=='/source':self.send_response(302);self.send_header('Location','/target');self.end_headers()
                else:received.append(self.headers.get('Authorization'));self.send_response(200);self.end_headers()
        server=http.server.ThreadingHTTPServer(('127.0.0.1',0),Handler);threading.Thread(target=server.serve_forever,daemon=True).start()
        try:
            client=urllib.request.build_opener(NoRedirect())
            with self.assertRaises(urllib.error.HTTPError) as error:client.open(urllib.request.Request('http://127.0.0.1:'+str(server.server_port)+'/source',headers={'Authorization':'Bearer unit-only-not-a-token'}))
            self.assertEqual(error.exception.code,302);self.assertEqual(received,[])
        finally:server.shutdown();server.server_close()
    def test_old_v7_api_and_issuer_can_never_be_restarted(self):
        e=object.__new__(Executor);e.old={role:'old-'+role for role in ('risk','keycloak','backend','gateway','frontend','ingress')}
        with patch('executor.run') as command:
            for name in e.old.values():
                with self.assertRaisesRegex(Blocked,'OLD_V7_START_FORBIDDEN'):e.start(name)
            command.assert_not_called()
    def test_rehearsal_cannot_select_live_project(self):
        with self.assertRaisesRegex(Blocked,'PROJECT_SCOPE'):Executor(self.plan(),'rehearsal')
    def test_live_cannot_select_legacy_lab(self):
        p=self.plan();p['project']='zerotrust-legacy-integration-20261026'
        with self.assertRaisesRegex(Blocked,'PROJECT_SCOPE'):Executor(p,'live')
    def test_go_binds_exact_plan_and_nonce(self):
        p=self.plan();a=self.approval(p);e=object.__new__(Executor);e.plan=p;e.hash=sha(canonical(p))
        with tempfile.TemporaryDirectory() as folder:
            file=Path(folder)/'approval.json'
            for field in ('nonce','plan_sha256','type'):
                broken=dict(a);broken[field]='wrong';file.write_text(json.dumps(broken))
                with self.assertRaises(Blocked):e.authorize(file)
    def test_each_maintenance_scope_requires_explicit_approval(self):
        p=self.plan();a=self.approval(p);e=object.__new__(Executor);e.plan=p;e.hash=sha(canonical(p))
        with tempfile.TemporaryDirectory() as folder:
            file=Path(folder)/'approval.json'
            for field in ('controlled_deployment','maintenance','force_fresh_login','temporary_fail_closed','designated_test_accounts','preserve_existing_pending'):
                broken=dict(a);broken[field]=False;file.write_text(json.dumps(broken))
                with self.assertRaisesRegex(Blocked,'SCOPE_INCOMPLETE'):e.authorize(file)
    def test_expired_go_rejected(self):
        p=self.plan();a=self.approval(p);a['expires_utc']='2000-01-01T00:00:00+00:00';e=object.__new__(Executor);e.plan=p;e.hash=sha(canonical(p))
        with tempfile.TemporaryDirectory() as folder:
            f=Path(folder)/'go.json';f.write_text(json.dumps(a))
            with self.assertRaisesRegex(Blocked,'EXPIRED'):e.authorize(f)
    def test_pending_or_accepted_stage_cannot_open_human_traffic(self):
        e=object.__new__(Executor)
        for stage in ('PREPARED','CLOSING','QUIESCED','CHECKPOINTED','MAINTENANCE','RESTORE_VERIFIED','ARTIFACTS_INSTALLED','GATES_PRIVATE','HOLD_FAIL_CLOSED'):
            e.j={'phase':stage}
            with self.assertRaisesRegex(Blocked,'HUMAN_TRAFFIC_MUST_REMAIN_CLOSED'):e.assert_openable()
    def test_foreign_container_cannot_be_stopped(self):
        e=object.__new__(Executor);e.allowed={'owned'}
        with patch('executor.run') as command:
            with self.assertRaisesRegex(Blocked,'FOREIGN_CONTAINER'):e.stop('protected-legacy-backup')
            command.assert_not_called()
    def test_source_volume_is_never_a_restore_target(self):
        e=object.__new__(Executor);e.project=REHEARSAL;e.id='a'*16;e.plan={'source_volumes':['protected-volume']}
        with self.assertRaisesRegex(Blocked,'FOREIGN_RESTORE_VOLUME'):e.load_volume('protected-volume',b'not-an-archive')
    def test_checkpoint_requires_quiescence(self):
        e=object.__new__(Executor);e.j={'phase':'PREPARED'}
        with self.assertRaisesRegex(Blocked,'QUIESCENCE'):e.checkpoint()
    def test_no_adoption_of_unowned_candidate(self):
        e=object.__new__(Executor);e.allowed={'owned'};e.old={};e.id='a'*16;e.project=REHEARSAL
        with patch('executor.inspect',return_value={'Config':{'Labels':{'io.zerotrust.d10.run':'other'}}}):
            with self.assertRaisesRegex(Blocked,'UNOWNED_D10_CONTAINER'):e.scope('owned')
    def test_native_acceptance_requires_every_security_predicate(self):
        e=object.__new__(Executor);e.j={'phase':'GATES_PRIVATE'};e.hash='bound';e.plan={'candidate_images':{'risk':'pin'}}
        receipt={'status':'PASS','plan_sha256':'bound','images':e.plan['candidate_images']}
        with self.assertRaisesRegex(Blocked,'ACCEPTANCE_INCOMPLETE'):e.mark_acceptance(receipt)
    def test_atomic_write_retries_transient_windows_rename_lock(self):
        from executor import write
        with tempfile.TemporaryDirectory() as folder:
            target=Path(folder)/'journal.json';real=Path.replace;calls=[]
            def flaky(self,dest):
                calls.append(1)
                if len(calls)<3:raise PermissionError(5,'Access is denied')
                return real(self,dest)
            with patch.object(Path,'replace',flaky),patch('executor.time.sleep'):write(target,{'phase':'X'})
            self.assertEqual(json.loads(target.read_text()),{'phase':'X'});self.assertEqual(len(calls),3)
            with patch.object(Path,'replace',side_effect=PermissionError(5,'Access is denied')),patch('executor.time.sleep'):
                with self.assertRaises(PermissionError):write(target,{'phase':'Y'})
            self.assertEqual(json.loads(target.read_text()),{'phase':'X'})
if __name__=='__main__':unittest.main()
