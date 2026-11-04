"""Environment isolation and relocation invariants; no Docker mutations."""
import copy
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import relocate_runtime as relocation
import zt
from test_zt import container


class EnvironmentTests(unittest.TestCase):
    def test_windows_desktop_mount_paths_resolve_to_host_drive(self):
        for prefix in ('/run/desktop/mnt/host/c/', '/host_mnt/c/', 'C:/'):
            self.assertEqual(zt.host_path(prefix + 'Users/test/runtime', windows=True).as_posix(),
                             'C:/Users/test/runtime')

    def test_linux_mount_paths_are_not_rewritten(self):
        source = '/run/desktop/mnt/host/c/Users/test/runtime'
        self.assertEqual(zt.host_path(source, windows=False).as_posix(), source)

    def test_lab_has_no_build_bootstrap_or_migration_and_uses_external_data(self):
        model = json.loads((zt.ROOT / 'compose.lab.yaml').read_text())
        self.assertEqual(set(model['services']), set(zt.SERVICES))
        for service in model['services'].values():
            self.assertNotIn('build', service)
            self.assertNotIn('profiles', service)
            for volume in service.get('volumes', []):
                if volume['type'] == 'bind':
                    self.assertIn('${ZT_LAB_RUNTIME:', volume['source'])
                    self.assertTrue(volume['read_only'])
                    self.assertFalse(volume['bind']['create_host_path'])
        self.assertEqual(len(model['volumes']), 4)
        for key, value in model['volumes'].items():
            self.assertEqual(value, {'external': True, 'name': f'{zt.PROJECT}_{key}'})
        self.assertEqual(model['services']['risk']['environment']['SPRING_FLYWAY_ENABLED'], 'false')
        self.assertEqual(model['services']['risk']['memswap_limit'], '1280m')

    def test_dev_uses_distinct_project_volumes_runtime_and_ports(self):
        content = (zt.ROOT / 'compose.dev.yaml').read_text()
        self.assertNotIn(zt.PROJECT, content)
        self.assertNotIn('ZT_LAB_RUNTIME', content)
        self.assertIn('name: zerotrust-demo', content)
        self.assertIn('./.local-demo', content)
        self.assertNotIn(':28443', content)
        for wrapper in ('scripts/demo/demo.cmd', 'scripts/demo/demo.ps1'):
            self.assertIn('compose.dev.yaml', (zt.ROOT / wrapper).read_text())

    def test_default_compose_cannot_bootstrap_any_environment(self):
        self.assertIn('services: {}', (zt.ROOT / 'compose.yaml').read_text())

    def test_copy_selection_excludes_history_and_detects_changed_file(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for role in relocation.ROLES.values():
                (root / role).mkdir()
                (root / role / 'test.conf').write_bytes(b'private-fixture')
            (root / 'migration-inputs').mkdir()
            (root / 'migration-inputs/export.json').write_text('excluded')
            files = relocation.runtime_files(root)
            self.assertEqual(len(files), len(relocation.ROLES))
            (root / 'risk/test.conf').write_bytes(b'changed')
            self.assertNotEqual(files, relocation.runtime_files(root))

    def test_running_service_rejected_before_any_recreation(self):
        rows = {s: container(s) for s in zt.SERVICES}
        rows['risk']['State']['Running'] = True
        with self.assertRaisesRegex(RuntimeError, 'stop the lab'):
            relocation.require_stopped(rows)

    def test_secret_values_never_appear_in_command_failure(self):
        with patch.object(relocation.subprocess, 'run', return_value=subprocess.CompletedProcess([], 1, b'PASSWORD=secret', b'private-secret')):
            with self.assertRaises(RuntimeError) as caught:
                relocation.run(['docker', 'compose', 'config'])
        self.assertNotIn('secret', str(caught.exception))

    def test_contract_detects_env_image_volume_or_memory_drift(self):
        original = container()
        baseline = relocation.contract(original)
        for area, key, value in [('Config', 'Env', ['SECRET=changed']),
                                 ('HostConfig', 'Memory', 1234)]:
            changed = copy.deepcopy(original)
            changed[area][key] = value
            self.assertNotEqual(baseline, relocation.contract(changed))
        changed = copy.deepcopy(original)
        changed['Image'] = 'new-image'
        self.assertNotEqual(baseline, relocation.contract(changed))
        changed['Mounts'] = [{'Type': 'volume', 'Name': 'other', 'Destination': '/data', 'RW': True}]
        self.assertNotEqual(baseline, relocation.contract(changed))

    def test_dns_defaults_allow_null_or_empty_but_not_an_explicit_server(self):
        original = container()
        original['HostConfig'].update(Dns=[], DnsSearch=[])
        changed = copy.deepcopy(original)
        changed['HostConfig'].update(Dns=None, DnsSearch=None)
        self.assertEqual(relocation.contract(original), relocation.contract(changed))
        changed['HostConfig']['Dns'] = ['192.0.2.1']
        self.assertNotEqual(relocation.contract(original), relocation.contract(changed))


if __name__ == '__main__':
    unittest.main()
