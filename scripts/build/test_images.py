import io
import json
from pathlib import Path
import tarfile
import unittest

import images


class BuildTests(unittest.TestCase):
    def test_private_and_generated_files_are_excluded(self):
        for path in ('frontend/.env.local', 'deploy/key.private.json', 'deploy/tls/server.key',
                     'src/../secrets.txt', 'frontend/node_modules/foo.js',
                     'risk-scoring-service/target/classes/a.class', '.git/config'):
            with self.subTest(path=path):
                self.assertFalse(images.eligible(path))
        self.assertTrue(images.eligible('src/main/resources/application.properties'))

    def test_archive_is_stable_and_preserves_exact_input_bytes(self):
        first = images.archive_bytes({'b.txt': b'2', 'a.txt': b'1\r\n'})
        self.assertEqual(first, images.archive_bytes({'a.txt': b'1\r\n', 'b.txt': b'2'}))
        with tarfile.open(fileobj=io.BytesIO(first)) as archive:
            self.assertEqual(archive.extractfile('a.txt').read(), b'1\r\n')
            self.assertGreater(archive.getmember('a.txt').mtime, 0)

    def test_all_steady_build_definitions_exist_and_enable_checks(self):
        model = json.loads((images.ROOT / 'compose.build.yaml').read_text())
        for service in images.SERVICES:
            filename, args = images.build_arguments(model, service)
            self.assertTrue((images.ROOT / filename).is_file(), filename)
            self.assertEqual(args['RUN_CHECKS'], 'true')
        self.assertEqual(model['services']['frontend']['build']['args']['KEYCLOAK_REALM'], 'DoAn')

    def test_cannot_skip_checks_or_escape_dockerfile_directory(self):
        for build in ({'dockerfile': '../Dockerfile'},
                      {'dockerfile': 'deploy/docker/Dockerfile.java', 'args': {'RUN_CHECKS': 'false'}}):
            with self.assertRaises(RuntimeError):
                images.build_arguments({'services': {'backend': {'build': build}}}, 'backend')

    def test_node_versions_match_ci_package_lock_and_docker(self):
        version = (images.ROOT / '.node-version').read_text().strip()
        package = json.loads((images.ROOT / 'frontend/package.json').read_text())
        lock = json.loads((images.ROOT / 'frontend/package-lock.json').read_text())
        self.assertEqual(package['engines']['node'], version)
        self.assertEqual(lock['packages']['']['engines']['node'], version)
        lines = (images.ROOT / 'deploy/docker/Dockerfile.frontend').read_text().splitlines()
        self.assertTrue(all(line.startswith(f'FROM node:{version}-') for line in lines if line.startswith('FROM ')))
        self.assertIn("node-version-file: '.node-version'", (images.ROOT / '.github/workflows/ci.yml').read_text())


if __name__ == '__main__':
    unittest.main()
