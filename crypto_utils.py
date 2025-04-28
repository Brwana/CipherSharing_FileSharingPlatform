from cryptography.hazmat.primitives.kdf.argon2 import Argon2id
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.hmac import HMAC

# Backend for cryptographic operations
backend = default_backend()

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

def generate_file_hash(file_data: bytes) -> bytes:
    """Generate SHA-256 hash of file data."""
    digest = hashes.Hash(hashes.SHA256())
    digest.update(file_data)
    return digest.finalize()

def generate_hmac(file_data: bytes, key: bytes) -> bytes:
    """Generate HMAC (for integrity + authenticity)."""
    hmac = HMAC(key, hashes.SHA256())
    hmac.update(file_data)
    return hmac.finalize()