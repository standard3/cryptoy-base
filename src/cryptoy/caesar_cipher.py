from cryptoy.utils import (
    str_to_unicodes,
    unicodes_to_str,
)

# TP: Chiffrement de César


def encrypt(msg: str, shift: int) -> str:
    """Encrypt a message using the Caesar cipher."""
    return unicodes_to_str([(x + shift) % 0x110000 for x in str_to_unicodes(msg)])


def decrypt(msg: str, shift: int) -> str:
    """Decrypt a message using the Caesar cipher."""
    return encrypt(msg, -shift)


def attack() -> tuple[str, int]:
    s = "恱恪恸急恪恳恳恪恲恮恸急恦恹恹恦恶恺恪恷恴恳恸急恵恦恷急恱恪急恳恴恷恩怱急恲恮恳恪恿急恱恦急恿恴恳恪"
    # Il faut déchiffrer le message s en utilisant l'information:
    # 'ennemis' apparait dans le message non chiffré

    # Code a placer ici, il faut return un couple (msg, shift)
    # ou msg est le message déchiffré, et shift la clef de chiffrage correspondant

    for shift in range(0x110000):
        msg = decrypt(s, shift)
        if "ennemis" in msg:
            return (msg, shift)
    # Si on ne trouve pas on lance une exception:
    raise RuntimeError("Failed to attack")
