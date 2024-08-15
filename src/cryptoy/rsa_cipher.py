from math import (
    gcd,
)

from cryptoy.utils import (
    draw_random_prime,
    int_to_str,
    modular_inverse,
    pow_mod,
    str_to_int,
)


def keygen() -> dict:
    """Generate a RSA key pair."""
    e = 65537

    # Randomly generate a prime number p with the function draw_random_prime
    p = draw_random_prime()

    # Randomly generate a prime number q with the function draw_random_prime
    q = draw_random_prime()

    # Compute n = p * q
    n = p * q
    phi = (p - 1) * (q - 1)
    d = modular_inverse(e, phi)

    return {"public_key": (e, n), "private_key": d}


def encrypt(msg: str, public_key: tuple) -> int:
    """Encrypt a message using the RSA cipher."""

    e, n = public_key
    msg_int = str_to_int(msg)

    if msg_int >= n:
        raise ValueError(
            "Le message est trop long pour être chiffré avec cette clé publique."
        )

    # Encrypt the message
    encrypted_msg = pow_mod(msg_int, e, n)

    return encrypted_msg


def decrypt(msg: int, key: dict) -> str:
    """Decrypt a message using the RSA cipher.

    Key will be a dictionary with the following format:
    { "public_key": (e, p * q), "private_key": d}
    """
    d = key["private_key"]
    n = key["public_key"][1]

    decrypted_int = pow_mod(msg, d, n)
    decrypted_msg = int_to_str(decrypted_int)

    return decrypted_msg
