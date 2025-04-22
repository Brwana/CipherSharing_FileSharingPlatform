import socket
import threading
import json
import os
import hashlib
from crypto_utils import encrypt_file, decrypt_file

class FileSharePeer:
    def __init__(self, host='localhost', port=9000):
        self.host = host
        self.port = port
        self.users_file = 'shared/users.json'
        self.shared_folder = 'shared/files'
        os.makedirs(self.shared_folder, exist_ok=True)
        os.makedirs(os.path.dirname(self.users_file), exist_ok=True)

        # Load users if users.json exists
        if os.path.exists(self.users_file):
            with open(self.users_file, 'r') as f:
                self.users = json.load(f)
        else:
            self.users = {}

        # Active sessions
        self.sessions = set()

    def save_users(self):
        with open(self.users_file, 'w') as f:
            json.dump(self.users, f)

    def hash_password(self, password):
        return hashlib.sha256(password.encode()).hexdigest()

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
                password = self.hash_password(request["password"])
                if username in self.users and self.users[username] == password:
                    self.sessions.add(username)
                    conn.send(json.dumps({"status": "success", "message": "Logged in"}).encode())
                else:
                    conn.send(json.dumps({"status": "error", "message": "Invalid credentials"}).encode())

            elif command in ["upload", "download"]:
                username = request.get("username")
                if username not in self.sessions:
                    conn.send(json.dumps({"status": "error", "message": "Authentication required"}).encode())
                    return

                if command == "upload":
                    filename = request["filename"]
                    filedata = bytes.fromhex(request["data"])
                    filepath = os.path.join(self.shared_folder, filename)
                    with open(filepath, 'wb') as f:
                        f.write(filedata)
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

if __name__ == "__main__":
    peer = FileSharePeer()
    peer.start()
