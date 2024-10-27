from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse, parse_qs
from datetime import datetime, timedelta
import sqlite3
import jwt
import json
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
import base64

hostName = "localhost"
serverPort = 8080
DB_PATH = "totally_not_my_privateKeys.db"

def int_to_base64(value):
    """Convert an integer to a Base64URL-encoded string"""
    value_hex = format(value, 'x')
    if len(value_hex) % 2 == 1:
        value_hex = '0' + value_hex
    value_bytes = bytes.fromhex(value_hex)
    encoded = base64.urlsafe_b64encode(value_bytes).rstrip(b'=')
    return encoded.decode('utf-8')

def init_db():
    """Initialize the SQLite database and create the keys table if not exists."""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS keys(
        kid INTEGER PRIMARY KEY AUTOINCREMENT,
        key BLOB NOT NULL,
        exp INTEGER NOT NULL
    )
    """)
    conn.commit()
    conn.close()

def generate_and_store_keys():
    """Generate and store both valid and expired keys in the SQLite database."""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    # Generate a valid key (expires in 1 hour)
    valid_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    valid_pem = valid_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )
    exp_valid = int((datetime.now() + timedelta(hours=1)).timestamp())
    cursor.execute("INSERT INTO keys (key, exp) VALUES (?, ?)", (valid_pem, exp_valid))
    
    # Generate an expired key (expired now)
    expired_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    expired_pem = expired_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )
    exp_expired = int(datetime.now().timestamp())
    cursor.execute("INSERT INTO keys (key, exp) VALUES (?, ?)", (expired_pem, exp_expired))
    
    conn.commit()
    conn.close()

class MyServer(BaseHTTPRequestHandler):

    def get_key_from_db(self, expired=False):
        """Fetches a valid or expired key based on the 'expired' parameter."""
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        current_time = int(datetime.now().timestamp())

        if expired:
            cursor.execute("SELECT key FROM keys WHERE exp <= ? ORDER BY exp DESC LIMIT 1", (current_time,))
        else:
            cursor.execute("SELECT key FROM keys WHERE exp > ? ORDER BY exp LIMIT 1", (current_time,))
        
        result = cursor.fetchone()
        conn.close()

        if result:
            return result[0]
        return None

    def sign_jwt(self, key_pem, kid):
        private_key = serialization.load_pem_private_key(
            key_pem, password=None
        )
        payload = {
            "username": "userABC",
            "exp": datetime.utcnow() + timedelta(hours=1)  # 1 hour expiry
        }
        headers = {
            "kid": str(kid)  # Add the kid to the JWT header
        }
        token = jwt.encode(payload, private_key, algorithm="RS256", headers=headers)
        return token


    def do_POST(self):
        parsed_path = urlparse(self.path)
        if parsed_path.path == "/auth":
            params = parse_qs(parsed_path.query)
            expired = 'expired' in params

            conn = sqlite3.connect(DB_PATH)
            cursor = conn.cursor()
            current_time = int(datetime.now().timestamp())

            if expired:
                cursor.execute("SELECT kid, key FROM keys WHERE exp <= ? ORDER BY exp DESC LIMIT 1", (current_time,))
            else:
                cursor.execute("SELECT kid, key FROM keys WHERE exp > ? ORDER BY exp LIMIT 1", (current_time,))
            
            result = cursor.fetchone()
            conn.close()

            if not result:
                self.send_response(404)
                self.end_headers()
                self.wfile.write(b"No key available")
                return

            kid, key_pem = result
            jwt_token = self.sign_jwt(key_pem, kid)

            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"token": jwt_token}).encode())


    def do_GET(self):
        parsed_path = urlparse(self.path)
        if parsed_path.path == "/.well-known/jwks.json":
            conn = sqlite3.connect(DB_PATH)
            cursor = conn.cursor()
            current_time = int(datetime.now().timestamp())

            # Select all non-expired keys
            cursor.execute("SELECT kid, key FROM keys WHERE exp > ?", (current_time,))
            keys = cursor.fetchall()
            conn.close()

            jwks = {
                "keys": []
            }

            for kid, key_pem in keys:
                public_key = serialization.load_pem_private_key(key_pem, password=None).public_key()
                public_numbers = public_key.public_numbers()
                jwks["keys"].append({
                    "kty": "RSA",
                    "kid": str(kid),
                    "n": int_to_base64(public_numbers.n),
                    "e": int_to_base64(public_numbers.e),
                    "alg": "RS256",
                    "use": "sig"
                })

            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps(jwks).encode())

# Run the server
if __name__ == "__main__":
    init_db()
    generate_and_store_keys()
    webServer = HTTPServer((hostName, serverPort), MyServer)
    print(f"Server started at http://{hostName}:{serverPort}")

    try:
        webServer.serve_forever()
    except KeyboardInterrupt:
        pass

    webServer.server_close()
    print("Server stopped.")
