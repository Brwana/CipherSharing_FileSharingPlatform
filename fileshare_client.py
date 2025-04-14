import socket
import json
import os


class FileShareClient:
    def __init__(self, host='localhost', port=9000):
        self.host = host
        self.port = port

    def send_request(self, request):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((self.host, self.port))
            s.send(json.dumps(request).encode())
            return json.loads(s.recv(8192).decode())

    def register(self, username, password):
        response = self.send_request({
            "command": "register",
            "username": username,
            "password": password
        })
        return response["message"]

    def login(self, username, password):
        response = self.send_request({
            "command": "login",
            "username": username,
            "password": password
        })
        return response["message"]

    def upload_file(self, filepath):
        if not os.path.exists(filepath):
            raise FileNotFoundError(f"{filepath} not found")

        with open(filepath, 'rb') as f:
            filedata = f.read()

        response = self.send_request({
            "command": "upload",
            "filename": os.path.basename(filepath),
            "data": filedata.hex()
        })
        return response["message"]

    def download_file(self, filename, save_path):
        response = self.send_request({
            "command": "download",
            "filename": filename
        })

        if response["status"] == "success":
            with open(save_path, 'wb') as f:
                f.write(bytes.fromhex(response["data"]))
            return "Download complete"
        return response["message"]


if __name__ == '__main__':
    # Create test file
    with open('test.txt', 'w') as f:
        f.write("This is a test file")

    client = FileShareClient()
    password = "secret123"

    print("Register:", client.register("nour", password))
    print("Login:", client.login("nour", password))
    print("Upload:", client.upload_file("test.txt"))
    print("Download:", client.download_file("test.txt", "received_test.txt"))