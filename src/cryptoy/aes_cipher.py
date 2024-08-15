from cryptography.hazmat.primitives.ciphers.aead import (
    AESGCM,
)


def encrypt(msg: bytes, key: bytes, nonce: bytes) -> bytes:
    """Encrypt a message using AES-GCM."""
    aesgcm = AESGCM(key)
    return aesgcm.encrypt(nonce, msg, None)


def decrypt(msg: bytes, key: bytes, nonce: bytes) -> bytes:
    """Decrypt a message using AES-GCM."""
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, msg, None)
