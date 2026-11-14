import os
import hashlib
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def generate_rsa_keypair():
    """Generates a 2048-bit RSA key pair in PEM format."""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    ).decode("utf-8")

    public_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode("utf-8")

    return private_pem, public_pem


def encrypt_aes_gcm(data: bytes):
    """
    Encrypts plaintext bytes with a generated one-time 256-bit AES key.
    Returns: (nonce + ciphertext, raw_aes_key)
    """
    aes_key = AESGCM.generate_key(bit_length=256)
    aesgcm = AESGCM(aes_key)
    nonce = os.urandom(12)
    ciphertext = nonce + aesgcm.encrypt(nonce, data, None)
    return ciphertext, aes_key


def decrypt_aes_gcm(encrypted_blob: bytes, aes_key: bytes) -> bytes:
    """
    Decrypts an AES-GCM ciphertext blob (first 12 bytes = nonce).
    """
    nonce = encrypted_blob[:12]
    ciphertext = encrypted_blob[12:]
    aesgcm = AESGCM(aes_key)
    return aesgcm.decrypt(nonce, ciphertext, None)


def encrypt_rsa_oaep(data: bytes, public_key_pem: str) -> bytes:
    """Encrypts data with RSA public key using OAEP (SHA-256) padding."""
    public_key = serialization.load_pem_public_key(public_key_pem.encode("utf-8"))
    return public_key.encrypt(
        data,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )


def decrypt_rsa_oaep(encrypted_data: bytes, private_key_pem: str) -> bytes:
    """Decrypts data with RSA private key using OAEP (SHA-256) padding."""
    private_key = serialization.load_pem_private_key(
        private_key_pem.encode("utf-8"),
        password=None
    )
    return private_key.decrypt(
        encrypted_data,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )


def compute_sha256(data: bytes) -> str:
    """Computes hexadecimal SHA-256 digest of data."""
    return hashlib.sha256(data).hexdigest()

