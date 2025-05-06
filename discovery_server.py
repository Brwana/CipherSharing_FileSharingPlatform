
import socket
import threading
import json
import os
import uuid
import requests

from crypto_utils import encrypt_file, decrypt_file
from argon2 import PasswordHasher

DISCOVERY_SERVER_URL = "http://localhost:8000"  # Change if hosted elsewhere
PEER_ADDRESS = "127.0.0.1:9000"  # Address used for registration

class FileSharePeer:
    def __init__(self, host='localhost', port=9000):
        self.host = host
        self.port = port
        self.users_file = 'shared/users.json'
        self.shared_folder = 'shared/files'
        os.makedirs(self.shared_folder, exist_ok=True)
        os.makedirs(os.path.dirname(self.users_file), exist_ok=True)

        self.sessions_file = 'shared/sessions.json'
        if os.path.exists(self.users_file):
            with open(self.users_file, 'r') as f:
                self.users = json.load(f)
        else:
            self.users = {}

        if os.path.exists(self.sessions_file) and os.path.getsize(self.sessions_file) > 0:
            with open(self.sessions_file, 'r') as f:
                self.sessions = json.load(f)
        else:
            self.sessions = {}

        self.file_ownership_file = 'shared/files_metadata.json'
        if os.path.exists(self.file_ownership_file) and os.path.getsize(self.file_ownership_file) > 0:
            with open(self.file_ownership_file, 'r') as f:
                self.file_ownership = json.load(f)
        else:
            self.file_ownership = {}

    def register_with_discovery(self):
        try:
            files = list(self.file_ownership.keys())
            data = {
                "command": "register_files",
                "peer": PEER_ADDRESS,
                "files": files
            }
            response = requests.post(f"{DISCOVERY_SERVER_URL}", json=data)
            print("[DISCOVERY] Registration:", response.json().get("message"))
        except Exception as e:
            print("[DISCOVERY] Error during registration:", e)

    def save_users(self):
        with open(self.users_file, 'w') as f:
            json.dump(self.users, f)

    def save_sessions(self):
        with open(self.sessions_file, 'w') as f:
            json.dump(self.sessions, f)

    def save_file_ownership(self):
        with open(self.file_ownership_file, 'w') as f:
            json.dump(self.file_ownership, f)

    def hash_password(self, password):
        return PasswordHasher().hash(password)

    def verify_password(self, hashed_password, input_password):
        try:
            return PasswordHasher().verify(hashed_password, input_password)
        except Exception:
            return False

    def handle_client(self, conn):
        try:
            data = conn.recv(4096).decode()
            request = json.loads(data)
            command = request.get("command")

            if command == "register":
                username = request["username"]
                password = self.hash_password(request["password"])
                if username in self.users:
                    conn.send(json.dumps({"status": "error", "message": "User already exists"}).encode())
                else:
                    self.users[username] = password
                    self.save_users()
                    conn.send(json.dumps({"status": "success", "message": "Registered"}).encode())

            elif command == "login":
                username = request["username"]
                input_password = request["password"]
                if username in self.users:
                    stored_hash = self.users[username]
                    if self.verify_password(stored_hash, input_password):
                        session_token = str(uuid.uuid4())
                        self.sessions[session_token] = username
                        conn.send(json.dumps({
                            "status": "success",
                            "message": "Logged in",
                            "token": session_token
                        }).encode())
                        self.save_sessions()
                    else:
                        conn.send(json.dumps({"status": "error", "message": "Invalid credentials"}).encode())
                else:
                    conn.send(json.dumps({"status": "error", "message": "Invalid credentials"}).encode())

            elif command in ["upload", "download", "list_files"]:
                token = request.get("token")
                username = self.sessions.get(token)
                if not username:
                    conn.send(json.dumps({"status": "error", "message": "Authentication required"}).encode())
                    return

                if command == "upload":
                    filename = request["filename"]
                    iv = bytes.fromhex(request["iv"])
                    data = bytes.fromhex(request["data"])
                    filepath = os.path.join(self.shared_folder, filename)
                    with open(filepath, 'wb') as f:
                        f.write(iv + data)
                    self.file_ownership[filename] = {
                        "owner": username,
                        "visibility": "public",
                        "allowed_users": []
                    }
                    self.save_file_ownership()
                    self.register_with_discovery()
                    conn.send(json.dumps({"status": "success", "message": "File uploaded"}).encode())

                elif command == "download":
                    filename = request["filename"]
                    file_path = os.path.join(self.shared_folder, filename)
                    if not os.path.exists(file_path):
                        conn.send(json.dumps({"status": "error", "message": "File not found"}).encode())
                        return
                    with open(file_path, 'rb') as f:
                        filedata = f.read()
                    conn.send(json.dumps({
                        "status": "success",
                        "data": filedata.hex()
                    }).encode())

                elif command == "list_files":
                    files = list(self.file_ownership.keys())
                    conn.send(json.dumps({"status": "success", "files": files}).encode())

            else:
                conn.send(json.dumps({"status": "error", "message": "Unknown command"}).encode())

        except Exception as e:
            conn.send(json.dumps({"status": "error", "message": str(e)}).encode())
        finally:
            conn.close()

    def start(self):
        self.register_with_discovery()
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind((self.host, self.port))
            s.listen()
            print(f"FileShare Peer listening on {self.host}:{self.port}")
            while True:
                conn, addr = s.accept()
                threading.Thread(target=self.handle_client, args=(conn,)).start()

if __name__ == "__main__":
    peer = FileSharePeer()
    peer.start()
