"""Canonical controller regression: reuse the 24 verified candidate fixtures.

No Docker subprocess, owner key, real journal/anchor or active state is used.
"""
import ast
import base64
import copy
import contextlib
import importlib.util
from pathlib import Path
import sys
import tempfile
import types
import unittest
from unittest import mock

HERE = Path(__file__).resolve().parent
ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'deploy/full-function'))
import network_v2_rollout as n
import promotion_executor as x
FIXTURES = ROOT / 'target/full-function-20261111b/network-v2-shadow/backup-failure-e7a7af43'
sys.path.insert(0, str(FIXTURES))
import owner_recovery_scope as scope


def adapter_classes(ctx, candidate=True, parent=None):
    # Compile the actual nested adapter definitions from the reviewed source;
    # do not duplicate the proposed implementation in the test.
    path = n.HERE / 'network_v2_rollout.py' if candidate else n.PACKAGE / 'history' / n.PREVIOUS_SHA / 'network_v2_rollout.py'
    tree = ast.parse(path.read_text(encoding='utf-8'))
    init = next(v for v in next(v for v in tree.body if isinstance(v, ast.ClassDef) and v.name == 'Context').body
                if isinstance(v, ast.FunctionDef) and v.name == '__init__')
    classes = [v for v in init.body if isinstance(v, ast.ClassDef) and v.name in ('BoundDocker', 'Executor')]
    module = types.SimpleNamespace(public_witness=lambda row: row['witness'], sealed_read=mock.Mock())
    env = dict(n.__dict__, ctx=ctx, module=module, original=x.Docker, parent=parent or x.Executor,
               PRIVATE=ctx.private)
    exec(compile(ast.fix_missing_locations(ast.Module(body=classes, type_ignores=[])), str(path), 'exec'), env)
    return env['BoundDocker'], env['Executor'], module


class ProbeTests(unittest.TestCase):
    def setUp(self):
        self.ctx = types.SimpleNamespace(m={'services': {'risk': {'name': 'baseline-risk', 'witness': 'risk'},
                                                        'backend': {'name': 'backend', 'witness': 'backend'}}},
                                         digest='fixture-manifest', private=Path('unused-fixture'),
                                         verify_replacement=mock.Mock())
        self.name = n.PROJECT + '-risk'
        self.ctx.m['services']['risk']['name'] = self.name
        self.row = {'Name': '/' + self.name, 'Image': n.OLD['risk'], 'witness': 'risk',
                    'Config': {'Labels': {'io.zerotrust.scope': n.PROJECT}},
                    'State': {'Running': True}, 'HostConfig': {'PortBindings': {}}}
        self.clock = mock.patch.object(x.time, 'monotonic', side_effect=[0, 181])
        self.clock.start(); self.addCleanup(self.clock.stop)
        self.sleep = mock.patch.object(x.time, 'sleep'); self.sleep.start(); self.addCleanup(self.sleep.stop)
        self.proc = mock.patch.object(x.subprocess, 'run', return_value=types.SimpleNamespace(returncode=0))
        self.run = self.proc.start(); self.addCleanup(self.proc.stop)

    def docker(self, candidate=True):
        cls, _, _ = adapter_classes(self.ctx, candidate)
        d = object.__new__(cls); d.inspect = mock.Mock(return_value=self.row)
        return d

    def test_reproduce_original_baseline_false_times_out_without_executing_TLS_probe(self):
        d = self.docker(False)
        with self.assertRaisesRegex(n.r.Rejected, '^OWNED_SERVICE_HEALTH_TIMEOUT$'):
            d.health(self.name, promoted=False)
        self.run.assert_not_called()

    def test_fixed_baseline_uses_TLS_even_when_inherited_backup_passes_false(self):
        self.docker().health(self.name, promoted=False)
        args = self.run.call_args.args[0]
        self.assertIn('https://risk:8443/actuator/health', args)
        self.assertEqual(self.run.call_args.kwargs['timeout'], 20)

    def test_fixed_candidate_also_uses_TLS(self):
        self.name = n.PROJECT + '-shadow-risk-fixture'
        self.row.update(Image=n.NEW['risk'])
        self.row['Config']['Labels'].update({'io.zerotrust.role': 'risk',
                                            'io.zerotrust.shadow.manifest': self.ctx.digest})
        self.docker().health(self.name, promoted=True)
        self.run.assert_called_once(); self.ctx.verify_replacement.assert_called()

    def test_native_healthy_backend_cannot_be_forced_onto_Risk_probe(self):
        self.name = n.PROJECT + '-backend'
        self.ctx.m['services']['backend']['name'] = self.name
        self.row.update(witness='backend', Image='not-a-risk-image')
        self.row['State']['Health'] = {'Status': 'healthy'}
        self.docker().health(self.name, promoted=True)
        self.run.assert_not_called()

    def test_TLS_failure_is_not_bypassed_and_reports_service_and_probe(self):
        self.run.return_value.returncode = 1
        with self.assertRaisesRegex(n.r.Rejected, 'service=risk probe=custom-TLS-CRL timeout=180'):
            self.docker().health(self.name, promoted=False)

    def test_native_health_failure_still_times_out(self):
        self.name = n.PROJECT + '-backend'
        self.ctx.m['services']['backend']['name'] = self.name
        self.row.update(witness='backend')
        with self.assertRaisesRegex(n.r.Rejected, 'service=backend probe=docker-healthcheck'):
            self.docker().health(self.name)
        self.run.assert_not_called()

    def test_exited_Risk_is_rejected_before_TLS(self):
        self.row['State']['Running'] = False
        with self.assertRaisesRegex(n.r.Rejected, 'OWNED_SERVICE_EXITED'):
            self.docker().health(self.name)
        self.run.assert_not_called()

    def test_foreign_ownership_rejected_before_probe(self):
        self.row['Config']['Labels']['io.zerotrust.scope'] = 'foreign-project'
        with self.assertRaisesRegex(n.r.Rejected, 'SHADOW_FOREIGN_CONTAINER'):
            self.docker().health(self.name)
        self.run.assert_not_called()

    def test_real_inherited_backup_precheck_now_reaches_key_preparation_without_quiescing(self):
        d = self.docker()
        e = object.__new__(x.Executor); e.d = d
        e.current = lambda: self.name
        e.new_operation = mock.Mock(return_value={'id': 'f' * 32, 'running_before': {'mysql': True, 'risk': True}})
        e.name = lambda service: self.name if service == 'risk' else service
        # All non-Risk services are healthy. Leave Risk without native Health.
        original_health = d.health
        d.health = lambda name, promoted=False: original_health(name, promoted) if name == self.name else None
        e.quiesce = mock.Mock()
        with mock.patch.object(x, 'storage_guard'), mock.patch.object(x, 'ProjectLock', contextlib.nullcontext), \
             mock.patch.object(x.AESGCM, 'generate_key', side_effect=RuntimeError('FIXTURE_STOP_BEFORE_KEY')):
            with self.assertRaisesRegex(RuntimeError, 'FIXTURE_STOP_BEFORE_KEY'):
                e.backup({'payload': {}})
        e.quiesce.assert_not_called(); self.run.assert_called_once()


class PreMutationJournalTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name); self.path = self.root / 'journal.json'
        self.ctx = types.SimpleNamespace(private=self.root, m={'services': {}}, digest='fixture-manifest',
                                         require_grant=mock.Mock())
        self.j = {'id': 'f' * 32, 'manifest': self.ctx.digest, 'operation': 'backup-only',
                  'status': 'RUNNING', 'stage': 'AUTHORIZED'}
        self.e = None

    def run_failure(self, *, existed=False, stage='AUTHORIZED', checkpoint=False, key=False, manifest=None,
                    expected_error='SIMULATED_PRECHECK_FAILURE'):
        if existed: self.path.write_text('fixture')
        if checkpoint: (self.root / 'checkpoints' / ('f' * 32)).mkdir(parents=True)
        if key:
            (self.root / 'keys').mkdir(); (self.root / 'keys' / ('f' * 32 + '.key')).write_text('test-only')
        self.j['stage'] = stage
        if manifest: self.j['manifest'] = manifest
        path = self.path
        class Parent:
            def backup(self, envelope):
                path.write_text('fixture-new-journal')
                raise n.r.Rejected('SIMULATED_PRECHECK_FAILURE')
        _, cls, module = adapter_classes(self.ctx, parent=Parent)
        e = object.__new__(cls); self.e = e
        e.journal = mock.Mock(return_value=self.path); e.finish = mock.Mock()
        module.sealed_read.return_value = self.j
        with self.assertRaisesRegex(n.r.Rejected, expected_error):
            e.backup({'payload': {'id': 'f' * 32}})
        return e

    def test_new_failed_precheck_journal_finishes_without_active_mutation(self):
        e = self.run_failure()
        e.finish.assert_called_once_with(self.j, result='REJECTED_BEFORE_ACTIVE_MUTATION')

    def test_existing_unfinished_journal_is_never_repaired_by_retry(self):
        self.run_failure(existed=True).finish.assert_not_called()

    def test_quiesced_or_checkpoint_work_requires_explicit_recovery(self):
        for stage in ('QUIESCING', 'QUIESCED', 'CHECKPOINT_WRITTEN'):
            with self.subTest(stage=stage):
                e = self.run_failure(stage=stage); e.finish.assert_not_called(); self.path.unlink()

    def test_partial_checkpoint_or_key_is_not_hidden(self):
        self.run_failure(checkpoint=True).finish.assert_not_called()

    def test_existing_key_requires_recovery(self):
        self.run_failure(key=True).finish.assert_not_called()

    def test_wrong_manifest_cannot_be_finished(self):
        self.run_failure(manifest='foreign').finish.assert_not_called()

    def test_no_grant_blocks_before_parent_or_journal_write(self):
        self.ctx.require_grant.side_effect = n.r.Rejected('NO_GRANT')
        self.run_failure(expected_error='NO_GRANT')
        self.assertFalse(self.path.exists())


class RecoveryScopeTests(unittest.TestCase):
    def setUp(self):
        # Public-only bytes; no owner signing, real key or grants.
        pub = b'F' * 32
        self.anchor = {'kind': 'OWNER_CONTROLLED_NETWORK_V2_SHADOW_ONLY', 'project': n.PROJECT,
                       'issuer': n.ISSUER, 'owner_sid': 'FIXTURE', 'descriptor_sha256': scope.DESCRIPTOR_SHA,
                       'packet_sha256': scope.PACKET_SHA, 'operations': sorted(scope.BASE_SCOPE),
                       'expires': 1, 'public_key': base64.b64encode(pub).decode(), 'public_key_sha256': n.sha(pub)}
        self.state = {'mode': 'BASELINE', 'manifest': scope.DESCRIPTOR_SHA}
        self.j = {'id': scope.OP, 'operation': 'backup-only', 'manifest': scope.DESCRIPTOR_SHA,
                  'status': 'RUNNING', 'stage': 'AUTHORIZED', 'before': dict(self.state),
                  'running_before': dict.fromkeys(n.SERVICES, True),
                  'request': {'id': scope.OP, 'operation': 'backup-only',
                              'descriptor_sha256': scope.DESCRIPTOR_SHA, 'packet_sha256': scope.PACKET_SHA}}

    def proposed(self, public_sha=None):
        return scope.proposed_anchor(self.anchor, {'owner_sid': 'FIXTURE'}, self.j, self.state,
                                     now=1000, public_sha=public_sha or self.anchor['public_key_sha256'])

    def test_only_recover_and_rollback_added_original_not_mutated(self):
        before = copy.deepcopy(self.anchor); result = self.proposed()
        self.assertEqual(set(result['operations']), scope.RECOVERY_SCOPE)
        self.assertEqual(self.anchor, before)
        self.assertEqual(result['expires'], 22600)
        self.assertEqual({k:v for k,v in result.items() if k not in ('expires','operations')},
                         {k:v for k,v in before.items() if k not in ('expires','operations')})

    def test_wrong_key_cannot_expand_scope(self):
        with self.assertRaisesRegex(n.r.Rejected, 'OWNER_KEY_MISMATCH'): self.proposed('wrong')

    def test_no_apply_or_restart_scope_is_accepted(self):
        self.anchor['operations'] += ['apply', 'restart']
        with self.assertRaisesRegex(n.r.Rejected, 'UNEXPECTED_EXISTING_SCOPE'): self.proposed()

    def test_other_operation_or_stage_cannot_expand_scope(self):
        for key, value in [('id', 'x' * 32), ('stage', 'QUIESCED'), ('operation', 'apply')]:
            before = dict(self.j); self.j[key] = value
            with self.subTest(key=key), self.assertRaisesRegex(n.r.Rejected, 'EXPECTED_PREQUIESCENCE'): self.proposed()
            self.j = before

    def test_changed_package_rejected(self):
        self.anchor['packet_sha256'] = 'wrong'
        with self.assertRaisesRegex(n.r.Rejected, 'ANCHOR_BINDING'): self.proposed()

    def test_changed_state_rejected(self):
        self.state['mode'] = 'SHADOW'
        with self.assertRaisesRegex(n.r.Rejected, 'BASELINE_STATE_CHANGED'): self.proposed()

    def test_stopped_running_intent_rejected(self):
        self.j['running_before']['risk'] = False
        with self.assertRaisesRegex(n.r.Rejected, 'BASELINE_STATE_CHANGED'): self.proposed()

    def test_missing_rollback_scope_remains_rejected_by_real_verifier(self):
        # Reuse exact verifier, test-only RAM signer; never creates an owner request.
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
        signer = Ed25519PrivateKey.generate()
        pub = signer.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        self.anchor.update(public_key=base64.b64encode(pub).decode(), public_key_sha256=n.sha(pub))
        m = {'owner_sid': 'FIXTURE', 'release': {}, 'checkpoint_rules': {}}
        with mock.patch.object(n.r, 'sha_file', side_effect=lambda p: scope.DESCRIPTOR_SHA if p == n.DESCRIPTOR else scope.PACKET_SHA):
            p = n.payload(m, 'recover', recover_of=scope.OP, recover_target='BASELINE', now=1000, ident='e' * 32)
        env = {'payload': p, 'signature': base64.b64encode(signer.sign(n.canonical(p))).decode()}
        proposed = self.proposed()
        self.assertEqual(n.verify(env, m, scope.DESCRIPTOR_SHA, scope.PACKET_SHA, 'recover', set(), proposed, now=1100)['recover_of'], scope.OP)
        proposed['operations'].remove('rollback')
        with self.assertRaisesRegex(n.r.Rejected, 'REQUIRES_ROLLBACK_SCOPE'):
            n.verify(env, m, scope.DESCRIPTOR_SHA, scope.PACKET_SHA, 'recover', set(), proposed, now=1100)


if __name__ == '__main__':
    unittest.main()
