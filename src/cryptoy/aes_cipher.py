from cryptography.hazmat.primitives.ciphers.aead import AESGCM

def encrypt(msg: bytes, key: bytes, nonce: bytes) -> bytes:
    # Create an AESGCM instance with the provided key
    aesgcm = AESGCM(key)
    # Use the encrypt method to encrypt the message with the given nonce
    ciphertext = aesgcm.encrypt(nonce, msg, None)
    return ciphertext

def decrypt(ciphertext: bytes, key: bytes, nonce: bytes) -> bytes:
    # Create an AESGCM instance with the provided key
    aesgcm = AESGCM(key)
    # Use the decrypt method to decrypt the ciphertext with the given nonce
    decrypted_msg = aesgcm.decrypt(nonce, ciphertext, None)
    return decrypted_msg
