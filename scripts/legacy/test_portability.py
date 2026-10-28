"""Compose-only regressions. No builds, containers, databases, credentials or migrations."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
PROJECT = 'zerotrust-legacy-integration-20261026'
STEADY = {'school', 'risk-db', 'keycloak-db', 'redis', 'keycloak', 'risk',
          'backend', 'frontend', 'gateway', 'crl'}


class ComposePortabilityTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='zerotrust-compose-')
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name).resolve()
        assert self.base.parent == Path(tempfile.gettempdir()).resolve()
        self.cwd = self.base / 'unrelated working directory'
        self.cwd.mkdir()
        self.env = os.environ.copy()
        for name in ('COMPOSE_FILE', 'COMPOSE_PROJECT_NAME', 'COMPOSE_PROFILES', 'LEGACY_STATE_DIR'):
            self.env.pop(name, None)

    def checkout(self, name):
        root = self.base / name
        root.mkdir(parents=True)
        for name in ('compose.yaml', '.env.example', '.env.legacy.example',
                     'scripts/legacy/compose_candidate.py'):
            destination = root / name
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / name, destination)
        # A developer's default .env must not leak into generated source.
        (root / '.env').write_text('COMPOSE_PROJECT_NAME=unrelated-project\n'
                                  'LEGACY_STATE_DIR=should-not-be-embedded\n')
        self.run_cli([sys.executable, str(root / 'scripts/legacy/compose_candidate.py')])
        return root

    def run_cli(self, command):
        result = subprocess.run(command, cwd=self.cwd, env=self.env,
                                capture_output=True, timeout=45)
        self.assertEqual(result.returncode, 0, result.stderr.decode(errors='replace'))
        return result.stdout

    def test_generator_is_independent_of_checkout_path_and_default_env(self):
        first = self.checkout('first checkout')
        second = self.checkout('nested/second checkout')
        content = (first / 'compose.legacy.yaml').read_bytes()
        self.assertEqual(content, (second / 'compose.legacy.yaml').read_bytes())
        model = json.loads(content)
        self.assertNotIn('should-not-be-embedded', content.decode())
        for service in model['services'].values():
            if 'build' in service:
                self.assertEqual(service['build']['context'], '.')
                self.assertFalse(Path(service['build']['dockerfile']).is_absolute())

    def test_resolved_paths_use_project_root_not_env_file_or_cwd(self):
        root = self.checkout('source')
        state = self.base / 'external-state'
        (state / 'risk').mkdir(parents=True)
        (state / 'risk/legacy-policy.env').write_text('# configuration validation only\n')
        env_dir = self.base / 'operator files'
        env_dir.mkdir()
        variables = env_dir / 'compose.env'
        variables.write_text('COMPOSE_PROJECT_NAME=unrelated-project\n'
                             'LEGACY_STATE_DIR=../external-state\n')
        model = json.loads(self.run_cli(['docker', 'compose', '--project-directory', str(root),
            '--project-name', PROJECT, '--env-file', str(variables),
            '-f', str(root / 'compose.legacy.yaml'), '--profile', 'legacy',
            'config', '--format', 'json']))
        self.assertEqual(model['name'], PROJECT)
        for service in model['services'].values():
            if 'build' in service:
                self.assertEqual(Path(service['build']['context']).resolve(), root.resolve())
        bind = next(v for v in model['services']['risk']['volumes'] if v['type'] == 'bind')
        self.assertEqual(Path(bind['source']).resolve(), (state / 'risk').resolve())

    def test_start_graph_excludes_bootstrap_import_and_synthetic_data(self):
        root = self.checkout('source')
        model = json.loads((root / 'compose.legacy.yaml').read_text())
        steady = {n for n, s in model['services'].items() if s.get('profiles') == ['legacy']}
        self.assertEqual(steady, STEADY)
        for name in steady:
            service = model['services'][name]
            self.assertLessEqual(set(service.get('depends_on', {})), steady)
            text = json.dumps(service)
            for forbidden in ('.local-demo', 'bootstrap.py', '--import-realm', 'qa02c-'):
                self.assertNotIn(forbidden, text)
        self.assertEqual(len(model['volumes']), 4)
        self.assertEqual(len(model['networks']), 2)
        self.assertEqual(model['services']['risk']['environment']['SPRING_FLYWAY_ENABLED'], 'false')
        self.assertNotIn('school-migrate', model['services'])
        school_check = model['services']['school-check']
        self.assertIn('/candidate/scripts/legacy/school_validate.py', school_check['command'])
        self.assertIn('check', school_check['command'])
        self.assertNotIn('apply', school_check['command'])
        self.assertNotIn('V20261026_01__legacy_teacher_schedule.sql', json.dumps(model))


if __name__ == '__main__':
    unittest.main()
