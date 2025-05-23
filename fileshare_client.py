import socket
import json
import os
from base64 import urlsafe_b64encode, urlsafe_b64decode
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from crypto_utils import encrypt_file, decrypt_file,generate_file_hash

class FileShareClient:
    def __init__(self, host='localhost', port=9000):
        self.host = host
        self.port = port
        self.username = None  # For display/UX
        self.token = None     # Token for authentication
        self.key = self._load_or_generate_key()

    # Add this method to the FileShareClient class
    def search_files(self, query):
        if not self.token:
            return "You must log in first."

        response = self.send_request({
            "command": "search",
            "token": self.token,
            "query": query
        })

        if response["status"] == "success":
            if not response["results"]:
                return "No files found matching your search."

            result_str = "Search Results:\n"
            for file_info in response["results"]:
                result_str += f"- {file_info['filename']} (owner: {file_info['owner']}, access: {file_info['access']})\n"
            return result_str
        else:
            return response["message"]
    def send_request(self, request):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((self.host, self.port))
            s.send(json.dumps(request).encode())
            return json.loads(s.recv(8192).decode())

    def _derive_key_from_password(self, password: str, salt: bytes, iterations: int = 100_000) -> bytes:
        """Derive a key from password using PBKDF2HMAC."""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=16,  # 128-bit key
            salt=salt,
            iterations=iterations,
            backend=default_backend()
        )
        return kdf.derive(password.encode())

    def _generate_key(self, key_length=16):
        """Generate a random AES key (16 bytes for AES-128)."""
        return os.urandom(key_length)

    def _load_or_generate_key(self):
        """Securely load or generate a key."""
        import os
        config_dir = os.path.expanduser("~/.config/fileshare_client")
        os.makedirs(config_dir, exist_ok=True, mode=0o700)
        key_file = os.path.join(config_dir, "client_key.bin")

        if os.path.exists(key_file):
            with open(key_file, "rb") as f:
                return f.read()
        else:
            key = os.urandom(16)
            with open(key_file, "wb") as f:
                f.write(key)
            os.chmod(key_file, 0o600)
            return key

    def register(self, username, password):
        # Generate salt for the user
        salt = os.urandom(16)

        # Derive password hash using PBKDF2HMAC
        password_hash = self._derive_key_from_password(password, salt)

        # Save salt for later logins
        self._save_user_salt(username, salt)

        # Send base64-encoded password hash to server
        response = self.send_request({
            "command": "register",
            "username": username,
            "password": urlsafe_b64encode(password_hash).decode()
        })
        return response["message"]
    def _save_user_salt(self, username: str, salt: bytes):
        config_dir = os.path.expanduser("~/.config/fileshare_client")
        os.makedirs(config_dir, exist_ok=True, mode=0o700)
        with open(os.path.join(config_dir, f"{username}_salt.bin"), "wb") as f:
            f.write(salt)

    def _load_user_salt(self, username: str) -> bytes:
        try:
            config_dir = os.path.expanduser("~/.config/fileshare_client")
            with open(os.path.join(config_dir, f"{username}_salt.bin"), "rb") as f:
                return f.read()
        except FileNotFoundError:
            return None

    def list_sessions(self):
        if not self.token:
            print("You must be logged in to list sessions.")
            return

        response = self.send_request({
            "command": "list_sessions",
            "token": self.token
        })

        if response["status"] == "success":
            print("\nActive Sessions:")
            for token, username in response["sessions"].items():
                print(f"- {username} (token: {token[:8]}...)")
        else:
            print(f"Error: {response.get('message', 'Unknown error')}")

    def login(self, username, password):
        salt = self._load_user_salt(username)
        if not salt:
            return "No saved salt for this user. Please register again."

        password_hash = self._derive_key_from_password(password, salt)

        response = self.send_request({
            "command": "login",
            "username": username,
            "password": urlsafe_b64encode(password_hash).decode()
        })
        if response["status"] == "success":
            self.username = username
            self.token = response["token"]
            self.key = self._derive_key_from_password(password, salt)  # 🔑 Use derived key for encryption
        return response["message"]

    def logout(self):
        if not self.token:
            print("Not currently logged in")
            return "Not logged in"

        try:
            # First verify the session exists
            if not self.check_session_status():
                self.username = None
                self.token = None
                return "Session already expired or invalid"

            # Send logout request
            response = self.send_request({
                "command": "logout",
                "token": self.token
            })

            if response.get("status") == "success":
                self.username = None
                self.token = None
                # print("Successfully logged out")
                return "Logged out successfully"

            return f"Logout failed: {response.get('message', 'Unknown error')}"

        except Exception as e:
            return f"Error during logout: {str(e)}"

    def upload_file(self):
        if not self.token:
            return "You must log in first."

        filename = input("Filename to upload (from current dir): ")
        upload_path = os.path.join(os.getcwd(), filename)
        if not os.path.exists(upload_path):
            return f"{filename} not found in the current directory"

        with open(upload_path, 'rb') as f:
            filedata = f.read()

        # Generate the hash (on plaintext)
        file_hash = generate_file_hash(filedata).hex()

        access = input("Set access status (public/private): ").strip().lower()
        allowed_users = []

        if access == "private":
            users = input("Enter usernames allowed (comma separated): ")
            allowed_users = [user.strip() for user in users.split(",")]

        # Encrypt the file
        iv, encrypted_data = encrypt_file(filedata, self.key)

        # Send to the server
        response = self.send_request({
            "command": "upload",
            "token": self.token,
            "filename": filename,
            "iv": iv.hex(),
            "data": encrypted_data.hex(),
            "hash": file_hash,  # ✅ Send the hash
            "access": access,
            "allowed_users": allowed_users
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
            filedata = bytes.fromhex(response["data"])
            file_hash_server = response.get("hash")  # ✅ Hash received from server
            iv = filedata[:16]
            encrypted_content = filedata[16:]

            # Decrypt
            decrypted_data = decrypt_file(iv, encrypted_content, self.key)

            # Verify integrity
            computed_hash = generate_file_hash(decrypted_data).hex()
            if computed_hash == file_hash_server:
                print("✅ Integrity Verified: File has not been modified.")
            else:
                print("⚠️ Warning: File integrity verification failed!")

            with open(save_path, 'wb') as f:
                f.write(decrypted_data)

            return "Download complete"
        return response["message"]

    def check_session_status(self):
        """Verify if current session is still valid"""
        if not self.token:
            print("No active session (no token)")
            return False

        try:
            response = self.send_request({
                "command": "check_session",
                "token": self.token
            })
            if response.get("status") == "success":
                print(f"Session valid for user: {response.get('username')}")
                return True
            print(f"Session invalid: {response.get('message', 'Unknown error')}")
            return False
        except json.JSONDecodeError:
            print("Error: Invalid response from server")
            return False
        except Exception as e:
            print(f"Error checking session: {str(e)}")
            return False

    def list_my_files(self):
        if not self.token:
            return "You must log in first."

        response = self.send_request({
            "command": "list_my_files",
            "token": self.token
        })
        return response.get("files", []) if response["status"] == "success" else response["message"]

    def list_all_files(self):
        if not self.token:
            return "You must log in first."

        response = self.send_request({
            "command": "list_files",
            "token": self.token
        })
        if response["status"] == "success":
            for file_info in response["files"]:
                if isinstance(file_info, dict):
                    print(f"{file_info['filename']} (uploaded by {file_info['owner']})")
                else:
                    print(file_info)  # fallback
            return "End of list."
        else:
            return response["message"]


if __name__ == '__main__':
    client = FileShareClient()
    print("Welcome to CipherShare!")

    while True:
        if not client.token:
            print("\nOptions: register, login, exit")
            choice = input("Enter command: ").strip().lower()

            if choice == "register":
                username = input("Username: ")
                password = input("Password: ")
                print(client.register(username, password))

            elif choice == "login":
                username = input("Username: ")
                password = input("Password: ")
                print(client.login(username, password))

            elif choice == "exit":
                break

            else:
                print("Invalid option.")

        else:
            print(
                "\nOptions: upload, download, list, list_my_files,search, logout, check_session, list_sessions, list_users, exit")
            choice = input("Enter command: ").strip().lower()

            if choice == "upload":
                print(client.upload_file())

            elif choice == "download":
                print(client.download_file())


            elif choice == "list":
                print("Shared Files:", client.list_all_files())

            elif choice == "list_my_files":
                print("Shared Files:", client.list_my_files())

            elif choice == "logout":
                print(client.logout())

            elif choice == "check_session":
                print(client.check_session_status())
            # In the main loop where other commands are handled, add:
            elif choice == "search":
                query = input("Enter search query: ")
                print(client.search_files(query))
            elif choice == "list_sessions":
                client.list_sessions()

            elif choice == "list_users":
                response = client.send_request({"command": "list_users"})
                if response["status"] == "success":
                    print("\nRegistered Users:")
                    for user in response["users"]:
                        print(f"- {user}")
                else:
                    print(f"Error: {response.get('message', 'Unknown error')}")

            elif choice == "exit":
                break

            else:
                print("Invalid option.")



