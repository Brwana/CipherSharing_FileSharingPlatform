import socket
import threading
import json
import os
import uuid
from crypto_utils import encrypt_file, decrypt_file
from argon2 import PasswordHasher


class FileSharePeer:
    def __init__(self, host='localhost', port=9000):
        self.host = host
        self.port = port
        self.users_file = 'shared/users.json'
        self.shared_folder = 'shared/files'
        os.makedirs(self.shared_folder, exist_ok=True)
        os.makedirs(os.path.dirname(self.users_file), exist_ok=True)

        if os.path.exists(self.users_file):
            with open(self.users_file, 'r') as f:
                self.users = json.load(f)
        else:
            self.users = {}

        self.sessions = {}  # session_token -> username

    def save_users(self):
        with open(self.users_file, 'w') as f:
            json.dump(self.users, f)

    def hash_password(self, password):
        return PasswordHasher().hash(password)

    def is_logged_in(self, username):
        """Check if user has an active session"""
        return username in self.sessions.values()

    def print_active_sessions(self):
        """Debug method to show active sessions"""
        print("\nActive Sessions:")
        for token, username in self.sessions.items():
            print(f"- {username} (token: {token[:8]}...)")
        print()

    def get_active_sessions(self):
        """Return all active sessions"""
        return self.sessions.copy()

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
                    else:
                        conn.send(json.dumps({"status": "error", "message": "Invalid credentials"}).encode())
                else:
                    conn.send(json.dumps({"status": "error", "message": "Invalid credentials"}).encode())
            elif command == "logout":
                token = request.get("token")
                if token in self.sessions:
                    del self.sessions[token]
                    conn.send(json.dumps({
                        "status": "success",
                        "message": "Logged out successfully"
                    }).encode())
                else:
                    conn.send(json.dumps({
                        "status": "error",
                        "message": "Invalid session"
                    }).encode())
            elif command in ["upload", "download", "list_files"]:
                token = request.get("token")
                username = self.sessions.get(token)
                if not username:
                    conn.send(json.dumps({"status": "error", "message": "Authentication required"}).encode())
                    return

                if command == "upload":
                    filename = request["filename"]
                    filedata = bytes.fromhex(request["data"])
                    iv = bytes.fromhex(request["iv"])

                    filepath = os.path.join(self.shared_folder, filename)
                    with open(filepath, 'wb') as f:
                        f.write(iv + filedata)  # store IV + encrypted file together

                    conn.send(json.dumps({"status": "success", "message": "Uploaded"}).encode())


                elif command == "download":
                    filename = request["filename"]
                    filepath = os.path.join(self.shared_folder, filename)
                    if os.path.exists(filepath):
                        with open(filepath, 'rb') as f:
                            filedata = f.read()
                        conn.send(json.dumps({"status": "success", "data": filedata.hex()}).encode())
                    else:
                        conn.send(json.dumps({"status": "error", "message": "File not found"}).encode())

                elif command == "list_files":
                    files = os.listdir(self.shared_folder)
                    conn.send(json.dumps({"status": "success", "files": files}).encode())


                elif command == "check_session":

                    token = request.get("token")

                    if token in self.sessions:

                        conn.send(json.dumps({

                            "status": "success",

                            "message": "Session active",

                            "username": self.sessions[token]

                        }).encode())

                    else:

                        conn.send(json.dumps({

                            "status": "error",

                            "message": "Invalid session"

                        }).encode())

        except Exception as e:
            conn.send(json.dumps({"status": "error", "message": str(e)}).encode())
        finally:
            conn.close()

    def start(self):
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.bind((self.host, self.port))
        server_socket.listen()
        print(f"Peer running on {self.host}:{self.port}")
        while True:
            client_conn, _ = server_socket.accept()
            threading.Thread(target=self.handle_client, args=(client_conn,)).start()
            self.print_active_sessions()


if __name__ == "__main__":
    peer = FileSharePeer()
    peer.start()
