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

    def upload_file(self, filename):
        # Path where files to be uploaded are stored
        upload_path = os.path.join(os.getcwd(), filename)

        if not os.path.exists(upload_path):
            raise FileNotFoundError(f"{filename} not found in the root directory")

        with open(upload_path, 'rb') as f:
            filedata = f.read()

        # Now the file will be uploaded to 'shared/files/'
        response = self.send_request({
            "command": "upload",
            "filename": filename,
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

    def list_files(self):
        response = self.send_request({
            "command": "list_files"
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

             filename = input("Filename to upload (from shared/files): ")

             print(client.upload_file(filename))


        elif choice == "download":

            filename = input("Filename to download: ")

            save_path = os.path.join(os.getcwd(), filename)  # Save in current working directory

            print(client.download_file(filename, save_path))


        elif choice == "list":
            print("Shared Files:", client.list_files())

        elif choice == "exit":
            break

        else:
            print("Invalid option.")


