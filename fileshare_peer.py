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
        if os.path.exists(self.users_file) and os.path.getsize(self.users_file) > 0:
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

    # Add this method to the FileSharePeer class
    def search_files(self, query, username):
        results = []
        query = query.lower()

        for filename, metadata in self.file_ownership.items():
            # Check if user has access to this file
            if metadata["visibility"] == "public" or \
                    username == metadata["owner"] or \
                    username in metadata.get("allowed_users", []):

                # Check if query matches filename or metadata
                if query in filename.lower():
                    results.append({
                        "filename": filename,
                        "owner": metadata["owner"],
                        "access": metadata["visibility"]
                    })

        return results
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

    def set_visibility_on_logout(self, username):
        for file, metadata in self.file_ownership.items():
            if metadata["owner"] == username:
                metadata["original_visibility"] = metadata["visibility"]
                metadata["visibility"] = "none"
        self.save_file_ownership()

    def restore_visibility_on_login(self, username):
        for file, metadata in self.file_ownership.items():
            if metadata["owner"] == username and metadata["visibility"] == "none":
                if "original_visibility" in metadata:
                    metadata["visibility"] = metadata.pop("original_visibility")
        self.save_file_ownership()

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
                        self.restore_visibility_on_login(username)
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

            elif command == "logout":
                token = request.get("token")
                username = self.sessions.pop(token, None)
                if username is not None:
                    self.set_visibility_on_logout(username)  # 👈 Hide files when user logs out
                    self.save_sessions()
                    conn.send(json.dumps({"status": "success", "message": "Logged out successfully"}).encode())

                else:
                    conn.send(json.dumps({"status": "error", "message": "Invalid session"}).encode())
            # Add this condition to the handle_client method's if-elif chain
            elif command == "search":
                token = request.get("token")
                username = self.sessions.get(token)
                if not username:
                    conn.send(json.dumps({"status": "error", "message": "Authentication required"}).encode())
                    return

                query = request.get("query", "")
                if not query:
                    conn.send(json.dumps({"status": "error", "message": "Empty search query"}).encode())
                    return

                results = self.search_files(query, username)
                conn.send(json.dumps({"status": "success", "results": results}).encode())
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
                    access = request.get("access", "public")
                    allowed_users = request.get("allowed_users", [])
                    file_hash = request.get("hash", "")  # ✅ Receive file hash

                    filepath = os.path.join(self.shared_folder, filename)
                    with open(filepath, 'wb') as f:
                        f.write(iv + data)

                    # Save metadata including hash
                    self.file_ownership[filename] = {
                        "owner": username,
                        "visibility": access,
                        "allowed_users": allowed_users,
                        "hash": file_hash  # ✅ Save hash
                    }
                    self.save_file_ownership()

                    conn.send(json.dumps({"status": "success", "message": "File uploaded"}).encode())



                elif command == "download":
                    filename = request["filename"]
                    file_path = os.path.join(self.shared_folder, filename)
                    if not os.path.exists(file_path):
                        conn.send(json.dumps({"status": "error", "message": "File not found"}).encode())
                        return
                    metadata = self.file_ownership.get(filename)
                    if not metadata:
                        conn.send(json.dumps({"status": "error", "message": "File metadata missing"}).encode())
                        return
                    visibility = metadata.get("visibility", "public")
                    allowed_users = metadata.get("allowed_users", [])
                    if visibility == "private" and username not in allowed_users and username != metadata.get("owner"):
                        conn.send(json.dumps({"status": "error", "message": "Access denied"}).encode())
                        return
                    with open(file_path, 'rb') as f:
                        filedata = f.read()
                    file_hash = metadata.get("hash", "")
                    conn.send(json.dumps({
                        "status": "success",
                        "data": filedata.hex(),
                        "hash": file_hash
                    }).encode())


                elif command == "list_files":
                    files = []
                    for filename, metadata in self.file_ownership.items():
                        if metadata["visibility"] == "public":
                            files.append({"filename": filename, "owner": metadata["owner"]})
                        elif metadata["visibility"] == "private":
                            if username in metadata.get("allowed_users", []) or username == metadata.get("owner"):
                                files.append({"filename": filename, "owner": metadata["owner"]})
                    conn.send(json.dumps({"status": "success", "files": files}).encode())


            elif command == "list_my_files":
                token = request.get("token")
                username = self.sessions.get(token)
                if not username:
                    conn.send(json.dumps({"status": "error", "message": "Invalid session"}).encode())
                    return

                files = [fname for fname, meta in self.file_ownership.items() if meta["owner"] == username]
                conn.send(json.dumps({"status": "success", "files": files}).encode())

            elif command == "check_session":
                token = request.get("token")
                username = self.sessions.get(token)
                if username:
                    conn.send(json.dumps({"status": "success", "username": username}).encode())
                else:
                    conn.send(json.dumps({"status": "error", "message": "Invalid session"}).encode())

            elif command == "list_users":
                usernames = list(self.users.keys())
                conn.send(json.dumps({"status": "success", "users": usernames}).encode())

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
