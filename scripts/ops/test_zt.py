"""Safety checks for the operations entrypoint; Docker is always mocked."""
import contextlib
import io
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import zt


def container(service='backend'):
    return {
        'Name': f'/{zt.PROJECT}-{service}', 'Id': 'container-id', 'Image': 'image-id',
        'Config': {'Image': 'application:version', 'Env': ['PASSWORD=never-export'],
                   'Labels': {'app.owner': zt.PROJECT,
                              'com.docker.compose.project': zt.PROJECT,
                              'com.docker.compose.service': service}},
        'State': {'Running': False, 'Status': 'exited', 'Health': {'Status': 'unhealthy'}},
        'HostConfig': {'PortBindings': {}}, 'NetworkSettings': {'Networks': {}},
        'Mounts': [],
    }


class OperationsTests(unittest.TestCase):
    def test_unavailable_engine_reports_docker_desktop(self):
        with patch.object(zt, 'docker_json', side_effect=RuntimeError('engine error')):
            with self.assertRaisesRegex(RuntimeError, 'Docker Engine unavailable'):
                zt.collect()

    def test_start_does_not_mutate_when_image_lock_is_invalid(self):
        with patch.object(zt, 'collect', return_value={'backend': container()}), \
                patch.object(zt, 'diagnose', return_value={'errors': []}), \
                patch.object(zt, 'check_configuration', side_effect=RuntimeError('image drift')), \
                patch.object(zt.legacy, 'main') as action, contextlib.redirect_stdout(io.StringIO()):
            with self.assertRaisesRegex(RuntimeError, 'image drift'):
                zt.main(['start'])
            action.assert_not_called()

    def test_rejects_wrong_project_service_owner_or_name(self):
        for field in ('app.owner', 'com.docker.compose.project', 'com.docker.compose.service'):
            info = container()
            info['Config']['Labels'][field] = 'other'
            with self.subTest(field=field), self.assertRaises(RuntimeError):
                zt.validate_identity('backend', info)
        info = container()
        info['Name'] = '/other'
        with self.assertRaises(RuntimeError):
            zt.validate_identity('backend', info)

    def test_inventory_excludes_environment_and_marks_stopped_health(self):
        result = zt.summarize({'backend': container()})
        self.assertNotIn('never-export', str(result))
        self.assertEqual(result['services']['backend']['health'], 'not_running')

    def test_missing_runtime_blocks_start_before_legacy_actions(self):
        with patch.object(zt, 'collect', return_value={'backend': container()}), \
                patch.object(zt.legacy, 'main') as action, contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(zt.main(['start']), 1)
            action.assert_not_called()

    def test_checks_files_without_reading_their_contents(self):
        info = container()
        with tempfile.TemporaryDirectory() as directory:
            info['Mounts'] = [{'Type': 'bind', 'Source': directory, 'Destination': '/run/demo'}]
            for filename in zt.REQUIRED_FILES['backend']:
                (Path(directory) / filename).write_text('private-value', encoding='utf-8')
            report = zt.diagnose({'backend': info})
            self.assertEqual(report['errors'], [])
            self.assertNotIn('private-value', str(report))
            (Path(directory) / 'jvm.args').unlink()
            self.assertTrue(zt.diagnose({'backend': info})['errors'])

    def test_wrong_volume_mapping_is_rejected(self):
        info = container('school')
        info['Mounts'] = [{'Type': 'volume', 'Name': 'other-data', 'Destination': '/var/lib/mysql'}]
        self.assertTrue(any('expected volume' in e for e in zt.diagnose({'school': info})['errors']))

    def test_missing_historical_compose_path_is_only_a_warning(self):
        info = container('frontend')
        info['Config']['Labels']['com.docker.compose.project.config_files'] = '/nonexistent/history.yaml'
        report = zt.diagnose({'frontend': info})
        self.assertEqual(report['errors'], [])
        self.assertTrue(any('historical Compose' in w for w in report['warnings']))

    def test_status_and_doctor_do_not_mutate_docker(self):
        for command in ('status', 'inventory', 'doctor'):
            with self.subTest(command=command), \
                    patch.object(zt, 'collect', return_value={'frontend': container('frontend')}), \
                    patch.object(zt.legacy, 'main') as mutation, \
                    patch.object(zt.subprocess, 'call') as call, \
                    contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(zt.main([command]), 0)
                mutation.assert_not_called()
                call.assert_not_called()

    def test_logs_uses_verified_id_and_argument_array(self):
        with patch.object(zt, 'collect', return_value={'backend': container()}), \
                patch.object(zt.subprocess, 'call', return_value=0) as call:
            self.assertEqual(zt.main(['logs', '--service', 'backend', '--tail', '5']), 0)
            call.assert_called_once_with(['docker', 'logs', '--tail', '5', 'container-id'])


if __name__ == '__main__':
    unittest.main()
