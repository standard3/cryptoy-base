import hashlib
import os
from random import (
    Random,
)

import names


def hash_password(password: str) -> str:
    return hashlib.sha3_256(password.encode()).hexdigest()


def random_salt() -> str:
    return bytes.hex(os.urandom(32))


def generate_users_and_password_hashes(
    passwords: list[str], count: int = 32
) -> dict[str, str]:
    rng = Random()  # noqa: S311

    users_and_password_hashes = {
        names.get_full_name(): hash_password(rng.choice(passwords))
        for _i in range(count)
    }
    return users_and_password_hashes


def attack(passwords: list[str], passwords_database: dict[str, str]) -> dict[str, str]:
    users_and_passwords = {}

    for user, hashed_password in passwords_database.items():
        for password in passwords:
            if hash_password(password) == hashed_password:
                users_and_passwords[user] = password
                break

    return users_and_passwords


def fix(
    passwords: list[str], passwords_database: dict[str, str]
) -> dict[str, dict[str, str]]:
    users_and_passwords = attack(passwords, passwords_database)

    users_and_salt = {}
    new_database = {}

    for user, password in users_and_passwords.items():
        salt = random_salt()
        hashed_password = hash_password(salt + password)
        new_database[user] = {"password_hash": hashed_password, "password_salt": salt}

    return new_database


def authenticate(
    user: str, password: str, new_database: dict[str, dict[str, str]]
) -> bool:
    if user in new_database:
        hashed_password = new_database[user]["password_hash"]
        salt = new_database[user]["password_salt"]
        return hash_password(salt + password) == hashed_password
    return False
