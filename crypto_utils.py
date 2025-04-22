from cryptography.hazmat.primitives.kdf.argon2 import Argon2id
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os
import base64
import secrets

# Backend for cryptographic operations
backend = default_backend()

# Hash password with Argon2id
def hash_password(password):
    salt = secrets.token_bytes(16)  # 128-bit salt
    argon2 = Argon2id(
        salt=salt,
        time_cost=16,
        memory_cost=65536,
        parallelism=2,
        hash_len=32,
        backend=backend
    )
    hashed_password = argon2.derive(password.encode('utf-8'))

    # Return hex-encoded values for storage
    return base64.b64encode(hashed_password).decode(), base64.b64encode(salt).decode()

# Verify password against stored hash and salt
def verify_password(password, stored_hash_b64, salt_b64):
    stored_hash = base64.b64decode(stored_hash_b64)
    salt = base64.b64decode(salt_b64)

    argon2 = Argon2id(
        salt=salt,
        time_cost=16,
        memory_cost=65536,
        parallelism=2,
        hash_len=32,
        backend=backend
    )
    try:
        argon2.verify(stored_hash, password.encode('utf-8'))
        return True
    except Exception:
        return False

# Derive AES key from password and salt using PBKDF2
def derive_key_from_password(password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=backend
    )
    return kdf.derive(password.encode('utf-8'))

# Encrypt file content with AES
def encrypt_file(data: bytes, key: bytes):
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=backend)
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(data) + encryptor.finalize()
    return iv, ciphertext

# Decrypt AES-encrypted file content
def decrypt_file(iv: bytes, ciphertext: bytes, key: bytes):
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=backend)
    decryptor = cipher.decryptor()
    return decryptor.update(ciphertext) + decryptor.finalize()
