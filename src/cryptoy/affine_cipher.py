from math import (
    gcd,
)

from cryptoy.utils import (
    str_to_unicodes,
    unicodes_to_str,
)

# TP: Chiffrement affine


def compute_permutation(a: int, b: int, n: int) -> list[int]:
    """Compute the permutation of the integers from
    0 to n-1 using the affine function f(x) = (a * x + b) % n
    """
    return [(a * i + b) % n for i in range(n)]


def compute_inverse_permutation(a: int, b: int, n: int) -> list[int]:
    """Compute the inverse permutation of the integers from
    0 to n-1 using the affine function f(x) = (a * x + b) % n
    """
    perm = compute_permutation(a, b, n)
    inv_perm = [-1] * n
    for i, j in enumerate(perm):
        inv_perm[j] = i
    return inv_perm


def encrypt(msg: str, a: int, b: int) -> str:
    """Encrypt a message using the affine cipher."""
    perm = compute_permutation(a, b, 0x110000)
    return unicodes_to_str([perm[x] for x in str_to_unicodes(msg)])


def encrypt_optimized(msg: str, a: int, b: int) -> str:
    """Encrypt a message using the affine cipher.

    It is an optimized version of the encrypt function."""
    return unicodes_to_str([(a * x + b) % 0x110000 for x in str_to_unicodes(msg)])


def decrypt(msg: str, a: int, b: int) -> str:
    """Decrypt a message using the affine cipher."""
    perm = compute_inverse_permutation(a, b, 0x110000)
    return unicodes_to_str([perm[x] for x in str_to_unicodes(msg)])


def decrypt_optimized(msg: str, a_inverse: int, b: int) -> str:
    """Decrypt a message using the affine cipher.

    It is an optimized version of the decrypt function."""
    return unicodes_to_str(
        [(a_inverse * (y - b)) % 0x110000 for y in str_to_unicodes(msg)]
    )


def compute_affine_keys(n: int) -> list[int]:
    """Compute the set of keys for the affine cipher."""
    return [a for a in range(1, n) if gcd(a, n) == 1]


def compute_affine_key_inverse(a: int, affine_keys: list, n: int) -> int:
    """Compute the inverse of a key for the affine cipher."""
    for m in affine_keys:
        if a * m % n == 1:
            return m
    raise RuntimeError(f"{a} has no inverse")


def attack() -> tuple[str, tuple[int, int]]:
    s = "࠾ੵΚઐ௯ஹઐૡΚૡೢఊஞ௯\u0c5bૡీੵΚ៚Κஞїᣍફ௯ஞૡΚր\u05ecՊՊΚஞૡΚՊեԯՊ؇ԯրՊրր"
    # trouver msg, a et b tel que affine_cipher_encrypt(msg, a, b) == s
    # avec comme info: "bombe" in msg et b == 58

    # Placer le code ici
    b = 58
    for a in compute_affine_keys(0x110000):
        msg = decrypt(s, a, b)
        if "bombe" in msg:
            return (msg, (a, b))

    raise RuntimeError("Failed to attack")


def attack_optimized() -> tuple[str, tuple[int, int]]:
    s = (
        "જഏ൮ൈ\u0c51ܲ೩\u0c51൛൛అ౷\u0c51ܲഢൈᘝఫᘝా\u0c51\u0cfc൮ܲఅܲᘝ൮ᘝܲాᘝఫಊಝ"
        "\u0c64\u0c64ൈᘝࠖܲೖఅܲఘഏ೩ఘ\u0c51ܲ\u0c51൛൮ܲఅ\u0cfc\u0cfcඁೖᘝ\u0c51"
    )
    # trouver msg, a et b tel que affine_cipher_encrypt(msg, a, b) == s
    # avec comme info: "bombe" in msg

    affine_keys = compute_affine_keys(0x110000)

    # Placer le code ici
    for a in affine_keys:
        a_inverse = compute_affine_key_inverse(a, affine_keys, 0x110000)
        for b in range(1, 10000):
            msg = decrypt_optimized(s, a_inverse, b)
            if "bombe" in msg:
                return msg, (a, b)

    raise RuntimeError("Failed to attack")
