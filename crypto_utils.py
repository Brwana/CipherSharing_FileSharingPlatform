from cryptography.hazmat.primitives.kdf.argon2 import Argon2id
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os
import secrets

# Backend for cryptographic operations
backend = default_backend()

def hash_password(password, salt=None):
    if salt is None:
        salt = secrets.token_bytes(16)  # Generate new salt if none provided
    argon2 = Argon2id(
        salt=salt,
        time_cost=16,  # Adjust these parameters based on performance/security trade-off
        memory_cost=65536,
        parallelism=2,
        hash_len=32,
        backend=backend
    )
    hashed_password = argon2.hash(password.encode('utf-8'))
    return hashed_password, salt  # Return both hash and salt

def verify_password(password, hashed_password, salt):
    argon2 = Argon2id(
        salt=salt,
        time_cost=16,
        memory_cost=65536,
        parallelism=2,
        hash_len=32,
        backend=backend
    )
    try:
        argon2.verify_hash(hashed_password, password.encode('utf-8'))
        return True  # Password is valid
    except:
        return False  # Password is invalid

def derive_key_from_password(password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,  # Key length for AES-256
        salt=salt,
        iterations=100000,  # Adjust iterations for security/performance
        backend=default_backend()
    )
    key = kdf.derive(password.encode('utf-8'))
    return key

def encrypt_file(data: bytes, key: bytes):
    iv = os.urandom(16)  # Generate a random initialization vector
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=backend)
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(data) + encryptor.finalize()  # Encrypt the data
    return iv, ciphertext  # Return iv and encrypted ciphertext

def decrypt_file(iv: bytes, ciphertext: bytes, key: bytes):
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=backend)
    decryptor = cipher.decryptor()
    return decryptor.update(ciphertext) + decryptor.finalize()  # Decrypt the ciphertext

def derive_key(password: str, salt: bytes):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100_000,
        backend=backend
    )
    return kdf.derive(password.encode())
