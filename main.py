# project 1 code and test suite provided by Professor.
# Andrew Kim
# CSCE 3550
# ak2555
from http.server import BaseHTTPRequestHandler, HTTPServer
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from urllib.parse import urlparse, parse_qs
import base64
import json
import jwt
import datetime
import sqlite3
from cryptography.hazmat.backends import default_backend

# Server configuration
hostName = "localhost"
serverPort = 8080

# database file name
database_path = "totally_not_my_privateKeys.db"
# table schema and init database function
# kid = primary key
# key = private key
# exp = timestamp expire
def init_database():
    con = sqlite3.connect(database_path)
    cur = con.cursor()
    cur.execute('''
        CREATE TABLE IF NOT EXISTS keys(
            kid INTEGER PRIMARY KEY AUTOINCREMENT,
            key BLOB NOT NULL,
            exp INTEGER NOT NULL
        )
    ''')
    con.commit()
    con.close()


# Save private keys to the DB
# Save key to database
def save_key_to_db(private_key_obj, expiration_timestamp):
    pem_bytes = private_key_obj.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )
    # put key in database
    con = sqlite3.connect(database_path)
    cur = con.cursor()
    cur.execute('INSERT INTO keys (key, exp) VALUES (?, ?)', (pem_bytes, expiration_timestamp))
    con.commit()
    # get key id generated
    kid = cur.lastrowid
    con.close()
    return kid

# Load key from database
def load_key_from_db(kid):
    con = sqlite3.connect(database_path)
    cur = con.cursor()
    cur.execute('SELECT key, exp FROM keys WHERE kid = ?', (kid,))
    result = cur.fetchone()
    con.close()
    # if key is found return private key
    if result:
        pem_bytes, exp = result
        private_key_obj = serialization.load_pem_private_key(
            pem_bytes,
            password=None,
            backend=default_backend()
        )
        return private_key_obj, exp
    return None, None

# Get one valid key from database
def get_valid_key():
    con = sqlite3.connect(database_path)
    cur = con.cursor()
    # get timestamp for current time
    current_time = int(datetime.datetime.utcnow().timestamp())
    # Find unexpired keys
    cur.execute('SELECT kid FROM keys WHERE exp > ? LIMIT 1', (current_time,))
    result = cur.fetchone()
    con.close()
    # return none if no valid keys
    if result:
        return result[0]
    return None

# Get one expired key from database
def get_expired_key():
    con = sqlite3.connect(database_path)
    cur = con.cursor()
    current_time = int(datetime.datetime.utcnow().timestamp())
    cur.execute('SELECT kid FROM keys WHERE exp <= ? LIMIT 1', (current_time,))
    result = cur.fetchone()
    con.close()
    if result:
        return result[0]
    return None

# Get every valid key in database
def get_all_valid_keys():
    con = sqlite3.connect(database_path)
    cur = con.cursor()
    current_time = int(datetime.datetime.utcnow().timestamp())
    cur.execute('SELECT kid FROM keys WHERE exp > ? ORDER BY kid', (current_time,))
    results = cur.fetchall()
    con.close()
    return [row[0] for row in results]

# Inititialize database for use
init_database()

# Generate private and expired key 
expired_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
)

private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
)



# Generate expired and valid keys and store into database
expired_timestamp = int((datetime.datetime.utcnow() - datetime.timedelta(hours=8)).timestamp())
expired_kid = save_key_to_db(expired_key, expired_timestamp)
private_valid_timestamp = int((datetime.datetime.utcnow() + datetime.timedelta(hours=1)).timestamp())
private_valid_kid = save_key_to_db(private_key, private_valid_timestamp)

#Load keys into private_key variable
private_key, expire_time = load_key_from_db(private_valid_kid)
if private_key is None:
    raise Exception("Failed to load valid key from database")
numbers = private_key.private_numbers()


# helper function
def int_to_base64(value):
    """Convert an integer to a Base64URL-encoded string"""
    value_hex = format(value, 'x')
    # Ensure even length
    if len(value_hex) % 2 == 1:
        value_hex = '0' + value_hex
    value_bytes = bytes.fromhex(value_hex)
    encoded = base64.urlsafe_b64encode(value_bytes).rstrip(b'=')
    return encoded.decode('utf-8')


class MyServer(BaseHTTPRequestHandler):
    def do_PUT(self):
        self.send_response(405)
        self.end_headers()
        return

    def do_PATCH(self):
        self.send_response(405)
        self.end_headers()
        return

    def do_DELETE(self):
        self.send_response(405)
        self.end_headers()
        return

    def do_HEAD(self):
        self.send_response(405)
        self.end_headers()
        return

    def do_POST(self):
        parsed_path = urlparse(self.path)
        params = parse_qs(parsed_path.query)
        if parsed_path.path == "/auth":
            kid = get_valid_key()
            headers = {
                "kid": str(kid)
            }
            token_payload = {
                "user": "username",
                "exp": int((datetime.datetime.utcnow() + datetime.timedelta(hours=1)).timestamp())
            }
            if 'expired' in params:
                kid = get_expired_key()
                headers["kid"] = str(kid)
                exp_time = datetime.datetime.utcnow() - datetime.timedelta(hours=1)
                token_payload["exp"] = int(exp_time.timestamp())
            
            loaded_key, exp = load_key_from_db(kid)
            if loaded_key is None:
                self.send_response(405)
                self.end_headers()
                return
            
            encoded_jwt = jwt.encode(token_payload, loaded_key, algorithm="RS256", headers=headers)
            self.send_response(200)
            self.end_headers()
            self.wfile.write(bytes(encoded_jwt, "utf-8"))
            return
            
        self.send_response(405)
        self.end_headers()
        return

    def do_GET(self):
        if self.path == "/.well-known/jwks.json":
            self.send_response(200)
            self.send_header("Content-type", "application/json")
            self.end_headers()

            # Get all valid keys from the database
            valid_kids = get_all_valid_keys()
            keys_list = []

            for kid in valid_kids:
                loaded_key, exp = load_key_from_db(kid)
                if loaded_key:
                    numbers = loaded_key.private_numbers()
                    keys_list.append({
                        "alg": "RS256",
                        "kty": "RSA",
                        "use": "sig",
                        "kid": str(kid),
                        "n": int_to_base64(numbers.public_numbers.n),
                        "e": int_to_base64(numbers.public_numbers.e),
                    })

            keys = {
                "keys": keys_list
            }
            self.wfile.write(bytes(json.dumps(keys), "utf-8"))
            return

        self.send_response(405)
        self.end_headers()
        return


if __name__ == "__main__":
    webServer = HTTPServer((hostName, serverPort), MyServer)
    try:
        webServer.serve_forever()
    except KeyboardInterrupt:
        pass

    webServer.server_close()
