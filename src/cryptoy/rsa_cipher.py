from math import gcd
from cryptoy.utils import (
    draw_random_prime,
    int_to_str,
    modular_inverse,
    pow_mod,
    str_to_int,
)

def keygen() -> dict:
    e = 65537
    # Step 1: Generate two random prime numbers p and q
    p = draw_random_prime()
    q = draw_random_prime()

    # Step 2: Calculate the private key d
    phi = (p - 1) * (q - 1)
    d = modular_inverse(e, phi)

    # Step 3: Return the keys as a dictionary
    return {"public_key": (e, p * q), "private_key": d}

def encrypt(msg: str, public_key: tuple) -> int:
    # Step 1: Convert the message to an integer
    msg_int = str_to_int(msg)

    # Step 2: Check if the integer is less than N (public_key[1])
    if msg_int >= public_key[1]:
        raise ValueError("Message is too large to encrypt with the given public key.")

    # Step 3: Encrypt the integer using pow_mod
    return pow_mod(msg_int, public_key[0], public_key[1])

def decrypt(msg: int, key: dict) -> str:
    # Step 1: Use pow_mod with the private key to decrypt the message
    decrypted_int = pow_mod(msg, key["private_key"], key["public_key"][1])

    # Step 2: Convert the decrypted integer to a string
    return int_to_str(decrypted_int)
