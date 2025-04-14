# fileshare_client.py
import socket
import json
import os
from crypto_utils import encrypt_file, decrypt_file, derive_key

class FileShareClient:
    def __init__(self, server_host='localhost', server_port=9000):
        self.server_host = server_host
        self.server_port = server_port

    def send_request(self, data):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((self.server_host, self.server_port))
            s.send(json.dumps(data).encode())
            response = s.recv(8192)
            return response

    def register(self, username, password):
        return self.send_request({"command": "register", "username": username, "password": password})

    def login(self, username, password):
        return self.send_request({"command": "login", "username": username, "password": password})

    def upload_file(self, filepath, password):
        with open(filepath, 'rb') as f:
            data = f.read()
        salt = os.urandom(16)
        key = derive_key(password, salt)
        iv, ciphertext = encrypt_file(data, key)
        payload = salt + iv + ciphertext
        filename = os.path.basename(filepath)
        return self.send_request({"command": "upload", "filename": filename, "data": payload.hex()})

    def download_file(self, filename, password, save_path):
        response = self.send_request({"command": "download", "filename": filename})
        if response.startswith(b"File not found"):
            print("File not found")
        else:
            payload = bytes.fromhex(response.decode())
            salt, iv, ciphertext = payload[:16], payload[16:32], payload[32:]
            key = derive_key(password, salt)
            data = decrypt_file(iv, ciphertext, key)
            with open(save_path, 'wb') as f:
                f.write(data)
            print("File downloaded and decrypted successfully")


if __name__ == '__main__':
    client = FileShareClient()
    print(client.register("nour", "secret123").decode())
    print(client.login("nour", "secret123").decode())
    password = "secret123"
    client.upload_file("test.txt", password)
    client.download_file("test.txt", password, "received_test.txt")
