import socket
import json
import os
from crypto_utils import encrypt_file, decrypt_file
import hashlib
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

# Define the AES key
key = b'my16byteaeskey12'

# Function to send a request to the server
def send_request(command_data):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect(('localhost', 9000))
        s.send(json.dumps(command_data).encode())
        response = s.recv(8192).decode()
        return json.loads(response)

# Function to hash a file for integrity check
def hash_file(filepath):
    sha256 = hashlib.sha256()
    with open(filepath, 'rb') as f:
        sha256.update(f.read())
    return sha256.hexdigest()

# 1. Register
print("Registering user1...")
print(send_request({"command": "register", "username": "user1", "password": "pass123"}))

# 2. Login
print("\nLogging in as user1...")
login_response = send_request({"command": "login", "username": "user1", "password": "pass123"})
print(login_response)
token = login_response.get("token")

if not token:
    print("Login failed; aborting tests.")
    exit()

# 3. Upload a file (encrypted)
print("\nUploading encrypted file...")
original_file = "testfile.txt"
encrypted_file = "testfile_encrypted.bin"
decrypted_file = "testfile_decrypted.txt"

# Write test content to a file
with open(original_file, "w") as f:
    f.write("Hello, secure world!")

# Read file content and encrypt it
with open(original_file, "rb") as f:
    file_data = f.read()

iv, encrypted_data = encrypt_file(file_data, key)
file_hash = hash_file(original_file)

upload_response = send_request({
    "command": "upload",
    "token": token,
    "filename": "testfile.txt",
    "iv": iv.hex(),
    "data": encrypted_data.hex(),
    "access": "private",
    "allowed_users": [],
    "hash": file_hash
})
print(upload_response)

# 4. List Files
print("\nListing accessible files...")
print(send_request({"command": "list_files", "token": token}))

# 5. Download the file and verify integrity
print("\nDownloading file...")
download_response = send_request({"command": "download", "token": token, "filename": "testfile.txt"})
print(download_response["status"], "-", download_response["message"] if "message" in download_response else "File downloaded")

if download_response["status"] == "success":
    data_bytes = bytes.fromhex(download_response["data"])
    iv = data_bytes[:16]
    encrypted_content = data_bytes[16:]

    decrypted_path = decrypted_file
    with open(encrypted_file, "wb") as ef:
        ef.write(encrypted_content)

    decrypted_data = decrypt_file(iv, encrypted_content, key)

    # Write decrypted data to a file
    with open(decrypted_path, "wb") as df:
        df.write(decrypted_data)

    downloaded_hash = hash_file(decrypted_path)
    print("Original Hash:", file_hash)
    print("Downloaded Hash:", downloaded_hash)
    assert downloaded_hash == download_response["hash"], "Hash mismatch! File may be corrupted."

# 6. Search file
print("\nSearching for 'test'...")
search_result = send_request({"command": "search", "token": token, "query": "test"})
print(search_result)

# 7. Logout and check if file becomes invisible
print("\nLogging out...")
print(send_request({"command": "logout", "token": token}))

print("\nTrying to list files after logout (should fail)...")
print(send_request({"command": "list_files", "token": token}))

# Clean up test files
os.remove(original_file)
os.remove(encrypted_file)
os.remove(decrypted_file)
