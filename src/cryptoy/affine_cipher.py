from math import (
    gcd,
)

from cryptoy.utils import (
    str_to_unicodes,
    unicodes_to_str,
)

# TP: Chiffrement affine

def compute_permutation(a: int, b: int, n: int) -> list[int]:
    
    result = []
    if gcd(a, n) == 0:
        raise RuntimeError(f"{a} nez pas premier avec {n} ")
        exit()
    for i in range (n):
        result.append((a * i + b) % n)
    
    return(result)
   


def compute_inverse_permutation(a: int, b: int, n: int) -> list[int]:
    
    perm = compute_permutation(a, b, n)       
    result = [0] * len(perm)
    for i,val in enumerate(perm):
        result[val] = i
    return result


def encrypt(msg: str, a: int, b: int) -> str:
    
    unicodes = str_to_unicodes(msg)
    perm = compute_permutation(a, b, 0x110000)
    for i in range(len(unicodes)):
        unicodes[i] = perm[unicodes[i]]
    return unicodes_to_str(unicodes)


def encrypt_optimized(msg: str, a: int, b: int) -> str:
    encrypted_message = []
    unicode_msg = str_to_unicodes(msg)
    for char in unicode_msg:
        encrypted_code = (a * char + b) % 0x110000
        encrypted_message.append(encrypted_code)
    return unicodes_to_str(encrypted_message)

def decrypt(msg: str, a: int, b: int) -> str:
    
    unicodes = str_to_unicodes(msg)
    perm = compute_inverse_permutation(a, b, 0x110000)
    for i in range(len(unicodes)):
        unicodes[i] = perm[unicodes[i]]
    return unicodes_to_str(unicodes)


def decrypt_optimized(msg: str, a_inverse: int, b: int) -> str:
    
    decrypted_message = []
    unicode_msg = str_to_unicodes(msg)
    for char in unicode_msg:
        decrypted_code = (a_inverse * (char - b)) % 0x110000
        decrypted_message.append(decrypted_code)
    return unicodes_to_str(decrypted_message)



def compute_affine_keys(n: int) -> list[int]:
    
    res = []
    for a in range(1,n):
        if (gcd(a, n) == 1):
            res.append(a)

    return res



def compute_affine_key_inverse(a: int, affine_keys: list, n: int) -> int:
    
    for i in affine_keys:
        if (a * i % n == 1):
            return i

    raise RuntimeError(f"{a} has no inverse")


def attack() -> tuple[str, tuple[int, int]]:
    s = "࠾ੵΚઐ௯ஹઐૡΚૡೢఊஞ௯\u0c5bૡీੵΚ៚Κஞїᣍફ௯ஞૡΚր\u05ecՊՊΚஞૡΚՊեԯՊ؇ԯրՊրր"
    
    a=1
    found = False
    while not found:
        decrypted = decrypt(s, a, 58)
        print(decrypted)
        if "bombe" in decrypted :
            found = True
            return decrypted, (a, 58)  
        else:
            a += 1

    if not found:
        raise RuntimeError("Failed to attack")

def attack_optimized() -> tuple[str, tuple[int, int]]:
    s = (
        "જഏ൮ൈ\u0c51ܲ೩\u0c51൛൛అ౷\u0c51ܲഢൈᘝఫᘝా\u0c51\u0cfc൮ܲఅܲᘝ൮ᘝܲాᘝఫಊಝ"
        "\u0c64\u0c64ൈᘝࠖܲೖఅܲఘഏ೩ఘ\u0c51ܲ\u0c51൛൮ܲఅ\u0cfc\u0cfcඁೖᘝ\u0c51"
    )
   
    msg = ""
    possibilites = compute_affine_keys(0x110000)
    for a in range(1,len(possibilites)):
        try:
            a_inverse = compute_affine_key_inverse(a, possibilites, 0x110000)
        except RuntimeError:
            continue
        for b in range(1,15000):
            msg = decrypt_optimized(s, a_inverse, b)
            if "bombe" in msg:
                return (msg, (a, b))

    raise RuntimeError("Failed to attack")

