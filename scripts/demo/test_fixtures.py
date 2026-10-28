"""Offline regression checks for fresh and previously prepared Demo inputs."""
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'deploy/demo'))
from fixtures import realm, school_seed


class ScorePortalFixturesTests(unittest.TestCase):
    def setUp(self):
        self.config = {
            'namespace': '00000000-0000-4000-8000-000000000001',
            'clients': {'zerotrust-risk-caller': 'test-only-marker'},
            'users': {
                actor: {'id': f'00000000-0000-4000-8000-{index:012d}',
                        'username': f'demo_{actor}', 'role': role, 'password': 'test-only-marker'}
                for index, (actor, role) in enumerate(
                    [('student', 'STUDENT'), ('student_b', 'STUDENT'),
                     ('admin', 'ADMIN'), ('high', 'STUDENT')], start=2)
            },
        }

    def test_realm_has_only_admin_and_student_business_roles(self):
        model = realm(self.config)
        self.assertEqual({role['name'] for role in model['roles']['realm']}, {'ADMIN', 'STUDENT'})
        people = [user for user in model['users'] if 'realmRoles' in user]
        self.assertEqual(len(people), 4)
        self.assertTrue(all(user['requiredActions'] == ['CONFIGURE_TOTP'] for user in people))
        self.assertFalse(next(client for client in model['clients']
                              if client['clientId'] == 'zerotrust-spa')['directAccessGrantsEnabled'])

    def test_school_seed_contains_only_score_portal_tables(self):
        sql = school_seed(self.config)
        tables = {line.split('INSERT INTO ', 1)[1].split('(', 1)[0]
                  for line in sql.splitlines() if line.startswith('INSERT INTO ')}
        self.assertEqual(tables, {'users', 'students', 'student_classes', 'subjects', 'scores'})
        self.assertEqual(sql.count('INSERT INTO students('), 3)
        self.assertEqual(sql.count('INSERT INTO scores('), 3)

    def test_old_teacher_input_does_not_provision_retired_users_or_tables(self):
        self.config['users']['teacher'] = {
            'id': '00000000-0000-4000-8000-000000000099',
            'username': 'demo_teacher', 'role': 'TEACHER', 'password': 'test-only-marker'}
        self.assertNotIn('demo_teacher', school_seed(self.config))
        self.assertNotIn('teachers(', school_seed(self.config))
        people = [user for user in realm(self.config)['users'] if 'realmRoles' in user]
        self.assertEqual(len(people), 4)
        self.assertNotIn('demo_teacher', {user['username'] for user in people})


if __name__ == '__main__':
    unittest.main()
