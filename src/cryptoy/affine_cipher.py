from math import (
    gcd,
)

from cryptoy.utils import (
    str_to_unicodes,
    unicodes_to_str,
)


def compute_permutation(a: int, b: int, n: int) -> list[int]:
    if gcd(a, n) == 0:
        raise RuntimeError
    return [(a * i + b) % n for i in range(n)]

def compute_inverse_permutation(a: int, b: int, n: int) -> list[int]:
    perm = compute_permutation(a, b, n)
    result = [0 for _ in range(n)]
    for i in range(len(perm)):
        result[perm[i]] = i
    return result

def encrypt(msg: str, a: int, b: int) -> str:
    result = str_to_unicodes(msg)
    perm = compute_permutation(a, b, 0x110000)
    
    for i in range(len(msg)):
        result[i] = perm[result[i]]
    return unicodes_to_str(result)
def encrypt_optimized(msg: str, a: int, b: int) -> str:
    result = []
    unicodes = str_to_unicodes(msg)
    for x in unicodes:
        result.append(((a * x + b) % 0x110000))
    return unicodes_to_str(result)

def decrypt(msg: str, a: int, b: int) -> str:
    result = str_to_unicodes(msg)
    perm = compute_inverse_permutation(a, b, 0x110000)

    for i in range(len(msg)):
        result[i] = perm[result[i]]
    return unicodes_to_str(result)

def decrypt_optimized(msg: str, a_inverse: int, b: int) -> str:
    result = []
    unicodes = str_to_unicodes(msg)
    for x in unicodes:
        result.append(((a_inverse * (x - b)) % 0x110000))
    return unicodes_to_str(result)

def compute_affine_keys(n: int) -> list[int]:
    result = []
    for a in range(n):
        if (a != 1 and gcd(a, n) == 1):
            result.append(a)
    return result

def compute_affine_key_inverse(a: int, affine_keys: list, n: int) -> int:
    for a_1 in affine_keys:
        if a * a_1 % n == 1:
            return a_1
    raise RuntimeError(f"{a} has no inverse")

def attack() -> tuple[str, tuple[int, int]]:
    s = "࠾ੵΚઐ௯ஹઐૡΚૡೢఊஞ௯\u0c5bૡీੵΚ៚Κஞїᣍફ௯ஞૡΚր\u05ecՊՊΚஞૡΚՊեԯՊ؇ԯրՊրր"
    key = 1
    for i in range(0x110000):
        if "bombe" in decrypt(s, key, 58):
            return decrypt(s, key, 58), (key, 58)
        key += 1
    raise RuntimeError("Failed to attack")

def attack_optimized() -> tuple[str, tuple[int, int]]:
    s = (
        "જഏ൮ൈ\u0c51ܲ೩\u0c51൛൛అ౷\u0c51ܲഢൈᘝఫᘝా\u0c51\u0cfc൮ܲఅܲᘝ൮ᘝܲాᘝఫಊಝ"
        "\u0c64\u0c64ൈᘝࠖܲೖఅܲఘഏ೩ఘ\u0c51ܲ\u0c51൛൮ܲఅ\u0cfc\u0cfcඁೖᘝ\u0c51"
    )

    keys = compute_affine_keys(0x110000)
    for a in range(1, len(keys)):
        try:
            a_inverse = compute_affine_key_inverse(a, keys, 0x110000)
        except RuntimeError:
            continue      
        for b in range(1, 10000):
            if "bombe" in decrypt_optimized(s, a_inverse, b):
                return decrypt_optimized(s, a_inverse, b), (a_inverse, b)
    raise RuntimeError("Failed to attack")

print(attack_optimized())
