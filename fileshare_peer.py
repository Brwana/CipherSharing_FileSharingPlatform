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
        self.file_ownership_file = 'shared/file_ownership.json'

        if os.path.exists(self.file_ownership_file) and os.path.getsize(self.sessions_file) > 0:
            with open(self.file_ownership_file, 'r') as f:
                self.file_ownership = json.load(f)
        else:
            self.file_ownership = {}

    def save_users(self):
        with open(self.users_file, 'w') as f:
            json.dump(self.users, f)

    def hash_password(self, password):
        return PasswordHasher().hash(password)

    def save_file_ownership(self):
        with open(self.file_ownership_file, 'w') as f:
            json.dump(self.file_ownership, f)

    def save_sessions(self):
        with open(self.sessions_file, 'w') as f:
            json.dump(self.sessions, f)

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
                        self.sessions[session_token] = username
                        self.save_sessions()

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
                    del self.sessions[token]
                    self.save_sessions()

                else:
                    conn.send(json.dumps({
                        "status": "error",
                        "message": "Invalid session"
                    }).encode())
            elif command == "list_sessions":
                # Optional: authenticate using token first
                token = request.get("token")
                if token in self.sessions:
                    conn.send(json.dumps({
                        "status": "success",
                        "sessions": self.sessions
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
                    iv = bytes.fromhex(request["iv"])
                    encrypted_data = bytes.fromhex(request["data"])

                    file_path = os.path.join(self.shared_folder, filename)
                    with open(file_path, 'wb') as f:
                        f.write(iv + encrypted_data)
                    # Bind the file to the user
                    self.file_ownership[filename] = username
                    self.save_file_ownership()

                    conn.send(json.dumps({"status": "success", "message": "File uploaded successfully"}).encode())

                elif command == "download":
                    filename = request["filename"]
                    file_path = os.path.join(self.shared_folder, filename)

                    if not os.path.exists(file_path):
                        conn.send(json.dumps({"status": "error", "message": "File not found"}).encode())
                        return

                    with open(file_path, 'rb') as f:
                        filedata = f.read()

                    # Send both IV and ciphertext as hex
                    conn.send(json.dumps({
                        "status": "success",
                        "data": filedata.hex()
                    }).encode())


                elif command == "list_files":

                    token = request["token"]

                    username = self.sessions.get(token)

                    if not username:
                        conn.send(json.dumps({"status": "error", "message": "Invalid session"}).encode())

                        return

                    files = os.listdir(self.shared_folder)

                    file_info = []

                    for file in files:
                        owner = self.file_ownership.get(file, "Unknown")

                        file_info.append({"filename": file, "owner": owner})

                    conn.send(json.dumps({"status": "success", "files": file_info}).encode())
            elif command == "list_my_files":

                token = request["token"]

                username = self.sessions.get(token)

                if not username:
                    conn.send(json.dumps({"status": "error", "message": "Invalid session"}).encode())

                    return

                files = os.listdir(self.shared_folder)

                file_info = []

                files = [fname for fname, owner in self.file_ownership.items() if owner == username]
                conn.send(json.dumps({"status": "success", "files": files}).encode())

                conn.send(json.dumps({"status": "success", "files": files}).encode())



            elif command == "check_session":
                token = request.get("token")
                username = self.sessions.get(token)
                if username:
                    conn.send(json.dumps({"status": "success", "username": username}).encode())
                else:
                    conn.send(json.dumps({"status": "error", "message": "Invalid session"}).encode())


            else:
                conn.send(json.dumps({"status": "error", "message": "Unknown command"}).encode())

        except Exception as e:
                    conn.send(json.dumps({"status": "error", "message": str(e)}).encode())
        finally:
                    conn.close()

    def start(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind((self.host, self.port))
            s.listen()
            print(f"FileShare Peer listening on {self.host}:{self.port}")

            while True:
                conn, addr = s.accept()
                print(f"Connection from {addr}")
                threading.Thread(target=self.handle_client, args=(conn,)).start()


if __name__ == "__main__":
    peer = FileSharePeer()
    peer.start()
