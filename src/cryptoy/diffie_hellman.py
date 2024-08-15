import random
import sys

from cryptoy.utils import (
    pow_mod,
)

sys.setrecursionlimit(5000)  # Required for pow_mod for large exponents


def keygen(prime_number: int, generator: int) -> dict[str, int]:
    """Generate a Diffie-Hellman key pair."""

    # Randomly generate a secret number private_key between 2 and prime_number - 1
    # inclusive with random.randint(min, max)
    private_key = random.randint(2, prime_number - 1)

    # compute the public key public_key = generator ** private_key % prime_number
    public_key = pow_mod(generator, private_key, prime_number)

    return {"public_key": public_key, "private_key": private_key}


def compute_shared_secret_key(public: int, private: int, prime_number: int) -> int:
    """Compute the shared secret key using the public key of the other
    participant and my private key.
    """
    return pow_mod(public, private, prime_number)
