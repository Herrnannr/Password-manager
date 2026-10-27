import pytest

from password_manager.core.crypto import KDFParameters, derive_key, generate_salt


@pytest.fixture
def fast_kdf() -> KDFParameters:
    return KDFParameters(time_cost=1, memory_cost=8192, parallelism=1)


@pytest.fixture
def test_salt() -> bytes:
    return b"\x01" * 16


@pytest.fixture
def key(fast_kdf, test_salt) -> bytes:
    return derive_key("test_password", test_salt, fast_kdf)

import os

import pytest

from password_manager.core.crypto import (
    KEY_SIZE,
    NONCE_SIZE,
    SALT_SIZE,
    KDFParameters,
    decrypt,
    encrypt,
)
from password_manager.core.errors import DecryptionError


def test_generate_salt_returns_correct_length():
    result = generate_salt()
    assert len(result) == SALT_SIZE


def test_generate_salt_is_unique():
    result1 = generate_salt()
    result2 = generate_salt()

    assert result1 != result2


def test_derive_key_returns_correct_length(fast_kdf):
    result = derive_key("test_master_password", generate_salt(), fast_kdf)
    assert len(result) == KEY_SIZE


def test_derive_key_is_deterministic(fast_kdf):
    salt = generate_salt()
    result1 = derive_key("test_master_password", salt, fast_kdf)
    result2 = derive_key("test_master_password", salt, fast_kdf)

    assert result1 == result2


def test_derive_key_known_value(fast_kdf):
    fixed_salt = b"\x00" * SALT_SIZE
    derived = derive_key("known_password", fixed_salt, fast_kdf)
    expected_hex = "11753867659519a5572371c3e844e5a3e5ba781866a9a958910d7449c5266d9d"
    
    assert derived.hex() == expected_hex


def test_derive_key_different_passwords_produce_different_keys(fast_kdf):
    salt = generate_salt()
    key1 = derive_key("password_one", salt, fast_kdf)
    key2 = derive_key("password_two", salt, fast_kdf)

    assert key1 != key2


def test_derive_key_empty_password_raises_value_error(fast_kdf):
    with pytest.raises(ValueError):
        derive_key("", generate_salt(), fast_kdf)


def test_derive_key_invalid_salt_length_raises_value_error(fast_kdf):
    with pytest.raises(ValueError):
        derive_key("test_master_password", os.urandom(8), fast_kdf)


def test_derive_key_enforces_production_defaults():
    params = KDFParameters()
    assert params.memory_cost >= 65536
    assert params.time_cost >= 2


def test_derive_key_nfkc_normalization(fast_kdf):
    password_composed = "\u00e9"
    password_decomposed = "\u0065\u0301"
    salt = generate_salt()

    key1 = derive_key(password_composed, salt, fast_kdf)
    key2 = derive_key(password_decomposed, salt, fast_kdf)

    assert key1 == key2


def test_encrypt_returns_tuple_with_nonce_and_ciphertext(key):
    content = b"my_secret_content"
    associated_data = b"metadata_context"

    nonce, encrypted_data = encrypt(key, content, associated_data)

    assert isinstance(nonce, bytes)
    assert len(nonce) == NONCE_SIZE
    assert isinstance(encrypted_data, bytes)
    assert len(encrypted_data) > 0


def test_encrypt_produces_unique_nonces_for_same_content(key):
    content = b"my_secret_content"
    associated_data = b"metadata_context"

    nonce1, ciphertext1 = encrypt(key, content, associated_data)
    nonce2, ciphertext2 = encrypt(key, content, associated_data)

    assert nonce1 != nonce2
    assert ciphertext1 != ciphertext2


def test_encrypt_invalid_key_length_raises_value_error():
    invalid_key = os.urandom(16)
    content = b"my_secret_content"
    associated_data = b"metadata_context"

    with pytest.raises(ValueError):
        encrypt(invalid_key, content, associated_data)


def test_encrypt_and_decrypt_roundtrip_success(key):
    content = b"my_secret_content"
    associated_data = b"metadata_context"

    nonce, encrypted_data = encrypt(key, content, associated_data)
    decrypted_content = decrypt(key, nonce, encrypted_data, associated_data)

    assert decrypted_content == content


@pytest.mark.parametrize("content", [b"", b"short", b"a" * 100])
def test_encrypt_and_decrypt_roundtrip_various_lengths(key, content):
    associated_data = b"metadata_context"
    nonce, encrypted_data = encrypt(key, content, associated_data)
    decrypted_content = decrypt(key, nonce, encrypted_data, associated_data)

    assert decrypted_content == content


def test_decrypt_empty_or_short_ciphertext_raises_decryption_error(key):
    nonce = os.urandom(NONCE_SIZE)
    associated_data = b"metadata_context"

    for invalid_ciphertext in [b"", b"short", os.urandom(10)]:
        with pytest.raises(DecryptionError):
            decrypt(key, nonce, invalid_ciphertext, associated_data)


def test_decrypt_wrong_key_raises_decryption_error(fast_kdf, test_salt):
    correct_key = derive_key("correct_password", test_salt, fast_kdf)
    wrong_key = derive_key("wrong_password", test_salt, fast_kdf)

    content = b"my_secret_content"
    associated_data = b"metadata_context"

    nonce, encrypted_data = encrypt(correct_key, content, associated_data)

    with pytest.raises(DecryptionError):
        decrypt(wrong_key, nonce, encrypted_data, associated_data)


@pytest.mark.parametrize("index", [0, -1])
def test_decrypt_tampered_ciphertext_raises_decryption_error(key, index):
    content = b"my_secret_content"
    associated_data = b"metadata_context"

    nonce, encrypted_data = encrypt(key, content, associated_data)

    tampered_bytes = bytearray(encrypted_data)
    tampered_bytes[index] ^= 0x01

    with pytest.raises(DecryptionError):
        decrypt(key, nonce, bytes(tampered_bytes), associated_data)


def test_decrypt_tampered_associated_data_raises_decryption_error(key):
    content = b"my_secret_content"
    associated_data = b"metadata_context"

    nonce, encrypted_data = encrypt(key, content, associated_data)
    wrong_associated_data = b"tampered_metadata"

    with pytest.raises(DecryptionError):
        decrypt(key, nonce, encrypted_data, wrong_associated_data)


def test_decrypt_invalid_key_length_raises_value_error(key):
    invalid_key = os.urandom(16)
    nonce = os.urandom(NONCE_SIZE)
    encrypted_data = os.urandom(32)
    associated_data = b"metadata"

    with pytest.raises(ValueError):
        decrypt(invalid_key, nonce, encrypted_data, associated_data)


def test_decrypt_invalid_nonce_length_raises_value_error(key):
    invalid_nonce = os.urandom(8)
    encrypted_data = os.urandom(32)
    associated_data = b"metadata"

    with pytest.raises(ValueError):
        decrypt(key, invalid_nonce, encrypted_data, associated_data)