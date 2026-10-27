import os
import unicodedata
from dataclasses import dataclass

from argon2 import Type
from argon2.low_level import hash_secret_raw
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .errors import DecryptionError

SALT_SIZE = 16
NONCE_SIZE = 12
KEY_SIZE = 32


@dataclass(frozen=True)
class KDFParameters:
    """Parameters configuration for the Argon2id Key Derivation Function (secure production defaults).
    
    Note: memory_cost is specified in KiB (e.g., 65536 KiB = 64 MiB).
    """
    time_cost: int = 2
    memory_cost: int = 65536
    parallelism: int = 1


def generate_salt() -> bytes:
    """Generates a cryptographically secure random salt of SALT_SIZE bytes."""
    return os.urandom(SALT_SIZE)


def derive_key(password: str, salt: bytes, kdf_parameters: KDFParameters) -> bytes:
    """Derives a secure cryptographic key from a master password using Argon2id."""
    if not password:
        raise ValueError("The password cannot be empty.")

    if len(salt) != SALT_SIZE:
        raise ValueError(f"The salt must have exactly {SALT_SIZE} bytes")

    password_bytes = unicodedata.normalize("NFKC", password).encode("utf-8")

    hash_bytes = hash_secret_raw(
        secret=password_bytes,
        salt=salt,
        time_cost=kdf_parameters.time_cost,
        memory_cost=kdf_parameters.memory_cost,
        parallelism=kdf_parameters.parallelism,
        hash_len=KEY_SIZE,
        type=Type.ID,
    )

    return hash_bytes


def encrypt(key: bytes, content: bytes, associated_data: bytes) -> tuple[bytes, bytes]:
    """Encrypts content using AES-GCM and returns a unique nonce alongside the ciphertext.

    Note: The returned encrypted_data includes the 16-byte authentication tag appended at the end.
    """
    if len(key) != KEY_SIZE:
        raise ValueError(f"The key must be exactly {KEY_SIZE} bytes")

    nonce = os.urandom(NONCE_SIZE)
    aesgcm = AESGCM(key)
    encrypted_data = aesgcm.encrypt(nonce, content, associated_data)

    return nonce, encrypted_data


def decrypt(key: bytes, nonce: bytes, encrypted_content: bytes, associated_data: bytes) -> bytes:
    """Decrypts AES-GCM ciphertext, mapping cryptographic failures to domain errors."""
    if len(key) != KEY_SIZE:
        raise ValueError(f"The key must be exactly {KEY_SIZE} bytes")

    if len(nonce) != NONCE_SIZE:
        raise ValueError(f"The nonce must have exactly {NONCE_SIZE} bytes")

    aesgcm = AESGCM(key)
    try:
        decrypted_content = aesgcm.decrypt(nonce, encrypted_content, associated_data)
        return decrypted_content

    except InvalidTag:
        raise DecryptionError(
            "Decryption error: the password is incorrect or the data has been altered."
        ) from None