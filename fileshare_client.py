import socket
import json
import os


class FileShareClient:
    def __init__(self, host='localhost', port=9000):
        self.host = host
        self.port = port
        self.username = None  # For display/UX
        self.token = None     # Token for authentication

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
        if response["status"] == "success":
            self.username = username
            self.token = response["token"]  # Save the token
        return response["message"]

    def upload_file(self):
        if not self.token:
            return "You must log in first."
        filename = input("Filename to upload (from current dir): ")
        upload_path = os.path.join(os.getcwd(), filename)
        if not os.path.exists(upload_path):
            return f"{filename} not found in the current directory"

        with open(upload_path, 'rb') as f:
            filedata = f.read()

        response = self.send_request({
            "command": "upload",
            "token": self.token,
            "filename": filename,
            "data": filedata.hex()
        })
        return response["message"]

    def download_file(self):
        if not self.token:
            return "You must log in first."
        filename = input("Filename to download: ")
        save_path = os.path.join(os.getcwd(), filename)
        response = self.send_request({
            "command": "download",
            "token": self.token,
            "filename": filename
        })

        if response["status"] == "success":
            with open(save_path, 'wb') as f:
                f.write(bytes.fromhex(response["data"]))
            return "Download complete"
        return response["message"]

    def list_files(self):
        if not self.token:
            return "You must log in first."

        response = self.send_request({
            "command": "list_files",
            "token": self.token
        })
        return response.get("files", []) if response["status"] == "success" else response["message"]



if __name__ == '__main__':
    client = FileShareClient()
    print("Welcome to CipherShare!")

    while True:
        print("\nOptions: register, login, upload, download, list, exit")
        choice = input("Enter command: ").strip().lower()

        if choice == "register":
            username = input("Username: ")
            password = input("Password: ")
            print(client.register(username, password))

        elif choice == "login":
            username = input("Username: ")
            password = input("Password: ")
            print(client.login(username, password))

        elif choice == "upload":
            print(client.upload_file())

        elif choice == "download":
            print(client.download_file())

        elif choice == "list":
            print("Shared Files:", client.list_files())

        elif choice == "exit":
            break

        else:
            print("Invalid option.")


