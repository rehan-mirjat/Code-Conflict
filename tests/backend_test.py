import os
import unittest
import tempfile
from backend.app import create_app

class BackendTestCase(unittest.TestCase):
    def setUp(self):
        self.db_fd, self.db_path = tempfile.mkstemp()
        self.app = create_app(db_path=self.db_path)
        self.app.config['TESTING'] = True
        self.client = self.app.test_client()

    def tearDown(self):
        os.close(self.db_fd)
        os.unlink(self.db_path)

    def test_health(self):
        res = self.client.get('/api/health')
        self.assertEqual(res.status_code, 200)
        self.assertTrue(res.get_json()['ok'])

    def test_register_and_login(self):
        # Register invalid email
        res = self.client.post('/api/register', json={
            'email': 'bademail@gmail.com',
            'password': 'Str0ng!Passphrase1'
        })
        self.assertEqual(res.status_code, 400)

        # Register valid email
        res = self.client.post('/api/register', json={
            'email': 'student@usindh.edu.pk',
            'password': 'Str0ng!Passphrase1'
        })
        self.assertEqual(res.status_code, 201)
        self.assertTrue(res.get_json()['ok'])

        # Duplicate register
        res = self.client.post('/api/register', json={
            'email': 'student@usindh.edu.pk',
            'password': 'Str0ng!Passphrase1'
        })
        self.assertEqual(res.status_code, 409)

        # Login wrong password
        res = self.client.post('/api/login', json={
            'email': 'student@usindh.edu.pk',
            'password': 'WrongPassword!1'
        })
        self.assertEqual(res.status_code, 401)

        # Login correct password
        res = self.client.post('/api/login', json={
            'email': 'student@usindh.edu.pk',
            'password': 'Str0ng!Passphrase1'
        })
        self.assertEqual(res.status_code, 200)
        self.assertTrue(res.get_json()['ok'])

        # Check me
        res = self.client.get('/api/me')
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.get_json()['user']['name'], 'student')

        # Logout
        res = self.client.post('/api/logout')
        self.assertEqual(res.status_code, 200)
        res = self.client.get('/api/me')
        self.assertIsNone(res.get_json()['user'])

    def test_contact(self):
        res = self.client.post('/api/contact', json={
            'name': 'Test User',
            'email': 'test@example.com',
            'subject': 'General Inquiry',
            'message': 'Testing message from test suite.'
        })
        self.assertEqual(res.status_code, 201)
        self.assertTrue(res.get_json()['ok'])

    def test_feed_next(self):
        res = self.client.get('/api/feed/next')
        self.assertEqual(res.status_code, 200)
        self.assertIn('item', res.get_json())

if __name__ == '__main__':
    unittest.main()
