
import socket
import json
import os
import requests

from crypto_utils import encrypt_file, decrypt_file, generate_file_hash

DISCOVERY_SERVER_URL = "http://localhost:8000"

class FileShareClient:
    def __init__(self):
        self.token = None
        self.peer_address = None

    def send_request(self, request, peer=None):
        if not peer:
            peer = self.peer_address
        host, port = peer.split(":")
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((host, int(port)))
            s.send(json.dumps(request).encode())
            return json.loads(s.recv(8192).decode())

    def discover_file(self, filename):
        try:
            response = requests.post(DISCOVERY_SERVER_URL, json={
                "command": "find_file",
                "filename": filename
            })
            return response.json().get("peers", [])
        except Exception as e:
            print(f"Discovery error: {e}")
            return []

    def register(self, username, password):
        response = self.send_request({
            "command": "register",
            "username": username,
            "password": password
        })
        return response["message"]

    def login(self, username, password, peer):
        self.peer_address = peer
        response = self.send_request({
            "command": "login",
            "username": username,
            "password": password
        })
        if response["status"] == "success":
            self.token = response["token"]
        return response["message"]

    def upload_file(self, filename):
        if not self.token:
            return "You must log in first."

        upload_path = os.path.join(os.getcwd(), filename)
        if not os.path.exists(upload_path):
            return f"{filename} not found"

        with open(upload_path, 'rb') as f:
            filedata = f.read()

        iv, encrypted_data = encrypt_file(filedata, b'secretAESkey1234')
        file_hash = generate_file_hash(filedata).hex()

        response = self.send_request({
            "command": "upload",
            "token": self.token,
            "filename": filename,
            "iv": iv.hex(),
            "data": encrypted_data.hex(),
            "hash": file_hash
        })
        return response["message"]

    def download_file(self, filename):
        peers = self.discover_file(filename)
        if not peers:
            return f"No peers found hosting '{filename}'"

        print(f"Available peers for {filename}:")
        for i, peer in enumerate(peers):
            print(f"{i + 1}: {peer}")
        choice = int(input("Choose peer to download from: ")) - 1

        selected_peer = peers[choice]
        response = self.send_request({
            "command": "download",
            "token": self.token,
            "filename": filename
        }, peer=selected_peer)

        if response["status"] == "success":
            filedata = bytes.fromhex(response["data"])
            iv = filedata[:16]
            ciphertext = filedata[16:]
            decrypted = decrypt_file(iv, ciphertext, b'secretAESkey1234')

            with open(filename, 'wb') as f:
                f.write(decrypted)
            return "Download complete"
        else:
            return response["message"]

    def list_files(self):
        response = self.send_request({
            "command": "list_files",
            "token": self.token
        })
        return response.get("files", []) if response["status"] == "success" else response["message"]

if __name__ == '__main__':
    client = FileShareClient()
    print("Welcome to CipherShare (Discovery Edition)")

    while True:
        print("\nOptions: register, login, upload, download, list, exit")
        choice = input("Enter command: ").strip().lower()

        if choice == "register":
            username = input("Username: ")
            password = input("Password: ")
            peer = input("Peer address (e.g., 127.0.0.1:9000): ")
            client.peer_address = peer
            print(client.register(username, password))

        elif choice == "login":
            username = input("Username: ")
            password = input("Password: ")
            peer = input("Peer address (e.g., 127.0.0.1:9000): ")
            print(client.login(username, password, peer))

        elif choice == "upload":
            filename = input("File to upload: ")
            print(client.upload_file(filename))

        elif choice == "download":
            filename = input("Filename to download: ")
            print(client.download_file(filename))

        elif choice == "list":
            print("Files:", client.list_files())

        elif choice == "exit":
            break

        else:
            print("Invalid option.")
