import unittest
import requests

BASE_URL = "http://localhost:8080"

class JWKS_ServerTests(unittest.TestCase):

    def test_auth_valid_token(self):
        """Test /auth endpoint for a valid token."""
        response = requests.post(f"{BASE_URL}/auth")
        self.assertEqual(response.status_code, 200)
        self.assertIn("token", response.json())

    def test_auth_expired_token(self):
        """Test /auth endpoint with expired parameter."""
        response = requests.post(f"{BASE_URL}/auth?expired=true")
        self.assertEqual(response.status_code, 200)
        self.assertIn("token", response.json())

    def test_jwks_endpoint(self):
        """Test /.well-known/jwks.json endpoint."""
        response = requests.get(f"{BASE_URL}/.well-known/jwks.json")
        self.assertEqual(response.status_code, 200)
        self.assertIn("keys", response.json())

if __name__ == "__main__":
    unittest.main()
