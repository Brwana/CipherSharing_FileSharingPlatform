# fileshare_peer.py
import socket
import threading
import json
import os
from crypto_utils import hash_password, verify_password

class FileSharePeer:
    def __init__(self, host='localhost', port=9000):
        self.host = host
        self.port = port
        self.users_file = 'shared/users.json'
        self.shared_folder = 'shared/files'
        os.makedirs(self.shared_folder, exist_ok=True)
        os.makedirs(os.path.dirname(self.users_file), exist_ok=True)
        self.load_users()

    def load_users(self):
        if os.path.exists(self.users_file):
            with open(self.users_file, 'r') as f:
                self.users = json.load(f)
        else:
            self.users = {}

    def save_users(self):
        with open(self.users_file, 'w') as f:
            json.dump(self.users, f)

    def handle_client(self, conn):
        try:
            data = conn.recv(4096).decode()
            request = json.loads(data)
            command = request.get("command")

            if command == "register":
                username = request["username"]
                password = request["password"]
                salt, pwd_hash = hash_password(password)
                self.users[username] = {
                    "salt": salt.hex(),
                    "hash": pwd_hash.hex()
                }
                self.save_users()
                conn.send(b"Registration successful")

            elif command == "login":
                username = request["username"]
                password = request["password"]
                user = self.users.get(username)
                if user and verify_password(bytes.fromhex(user["hash"]), password, bytes.fromhex(user["salt"])):
                    conn.send(b"Login successful")
                else:
                    conn.send(b"Login failed")

            elif command == "upload":
                filename = request["filename"]
                filedata = bytes.fromhex(request["data"])
                filepath = os.path.join(self.shared_folder, filename)
                with open(filepath, 'wb') as f:
                    f.write(filedata)
                conn.send(b"Upload complete")

            elif command == "download":
                filename = request["filename"]
                filepath = os.path.join(self.shared_folder, filename)
                if os.path.exists(filepath):
                    with open(filepath, 'rb') as f:
                        filedata = f.read()
                    conn.send(json.dumps(filedata.hex()).encode())
                else:
                    conn.send(b"File not found")
        except Exception as e:
            print(f"Error: {e}")
        finally:
            conn.close()

    def start(self):
        try:
            server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server_socket.bind((self.host, self.port))
            server_socket.listen()
            print(f"Peer running on {self.host}:{self.port}")
            while True:
                client_conn, _ = server_socket.accept()
                threading.Thread(target=self.handle_client, args=(client_conn,), daemon=True).start()
        except Exception as e:
            print(f"Error starting server: {e}")

if __name__ == "__main__":
    peer = FileSharePeer()  # Uses default host='localhost', port=9000
    peer.start()  # Starts the server