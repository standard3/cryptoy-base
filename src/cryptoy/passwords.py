import hashlib
import os
from random import (
    Random,
)

import names


def hash_password(password: str) -> str:
    """Hash a password using the SHA-3-256 algorithm."""
    return hashlib.sha3_256(password.encode()).hexdigest()


def random_salt() -> str:
    """Generate a random salt."""
    return bytes.hex(os.urandom(32))


def generate_users_and_password_hashes(
    passwords: list[str], count: int = 32
) -> dict[str, str]:
    """Generate a dictionary of users and their password hashes."""
    rng = Random()  # noqa: S311

    users_and_password_hashes = {
        names.get_full_name(): hash_password(rng.choice(passwords))
        for _i in range(count)
    }
    return users_and_password_hashes


def attack(passwords: list[str], passwords_database: dict[str, str]) -> dict[str, str]:
    users_and_passwords = {}

    # A implémenter
    # Doit calculer le mots de passe de chaque utilisateur grace à une attaque par dictionnaire
    hashes = {hash_password(password): password for password in passwords}

    users_and_passwords = {
        user: hashes[hashed_password]
        for user, hashed_password in passwords_database.items()
    }
    return users_and_passwords


def fix(
    passwords: list[str], passwords_database: dict[str, str]
) -> dict[str, dict[str, str]]:
    users_and_passwords = attack(passwords, passwords_database)

    users_and_salt = {user: random_salt() for user in users_and_passwords}
    new_database = {
        user: {
            "password_hash": hash_password(users_and_salt[user] + password),
            "password_salt": users_and_salt[user],
        }
        for user, password in users_and_passwords.items()
        # for user, salt, password in zip(users_and_passwords, users_and_salt.values(), users_and_password
    }

    # A implémenter
    # Doit calculer une nouvelle base de donnée ou chaque élement est un dictionnaire de la forme:
    # {
    #     "password_hash": H,
    #     "password_salt": S,
    # }
    # tel que H = hash_password(S + password)

    return new_database


def authenticate(
    user: str, password: str, new_database: dict[str, dict[str, str]]
) -> bool:
    # Doit renvoyer True si l'utilisateur a envoyé le bon password, False sinon
    candidate_hash = hash_password(new_database[user]["password_salt"] + password)
    return candidate_hash == new_database[user]["password_hash"]
