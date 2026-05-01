"""Input validation tests.

Verifies that the public API rejects malformed inputs at the boundary
rather than letting them propagate into the cryptographic core.
"""

# External Imports
import pytest

# Project Imports
from a23crypt import decrypt, encrypt
from a23crypt.constants import (
    CONTEXT_MAX_BYTES,
    KEY_SIZE_BYTES,
    MAX_SINGLE_SHOT_CIPHERTEXT_BYTES,
    MAX_SINGLE_SHOT_SIZE_BYTES,
    ZSTD_MAX_LEVEL,
)
from a23crypt.errors import InputSizeError, InvalidKeyError

# Test Imports
from tests.conftest import CLIENT_KEY, RECORD_KEY, SERVER_KEY


# ---------------------------------------------------------------------------
# Key size validation
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("size", [0, 1, 15, 16, 24, 31, 33, 48, 64, 100])
def test_server_key_wrong_size_rejected(size):
    if size == KEY_SIZE_BYTES:
        pytest.skip("KEY_SIZE_BYTES itself is valid")
    with pytest.raises(InvalidKeyError, match="server_key"):
        encrypt(
            b"data",
            server_key=b"x" * size,
            client_key=CLIENT_KEY,
            record_key=RECORD_KEY,
        )


@pytest.mark.parametrize("size", [0, 1, 15, 16, 24, 31, 33, 48, 64, 100])
def test_client_key_wrong_size_rejected(size):
    if size == KEY_SIZE_BYTES:
        pytest.skip("KEY_SIZE_BYTES itself is valid")
    with pytest.raises(InvalidKeyError, match="client_key"):
        encrypt(
            b"data",
            server_key=SERVER_KEY,
            client_key=b"x" * size,
            record_key=RECORD_KEY,
        )


def test_decrypt_also_validates_key_sizes():
    with pytest.raises(InvalidKeyError):
        decrypt(
            b"placeholder",
            server_key=b"short",
            client_key=CLIENT_KEY,
            record_key=RECORD_KEY,
        )
    with pytest.raises(InvalidKeyError):
        decrypt(
            b"placeholder",
            server_key=SERVER_KEY,
            client_key=b"short",
            record_key=RECORD_KEY,
        )


# ---------------------------------------------------------------------------
# record_key validation
# ---------------------------------------------------------------------------


def test_empty_record_key_rejected():
    with pytest.raises(InvalidKeyError, match="record_key"):
        encrypt(
            b"data",
            server_key=SERVER_KEY,
            client_key=CLIENT_KEY,
            record_key=b"",
        )


@pytest.mark.parametrize(
    "size",
    [CONTEXT_MAX_BYTES + 1, CONTEXT_MAX_BYTES + 100, CONTEXT_MAX_BYTES * 2],
    ids=lambda n: f"size={n}",
)
def test_oversized_record_key_rejected(size):
    with pytest.raises(InvalidKeyError, match="record_key"):
        encrypt(
            b"data",
            server_key=SERVER_KEY,
            client_key=CLIENT_KEY,
            record_key=b"x" * size,
        )


@pytest.mark.parametrize("size", [1, 7, 64, 1024, CONTEXT_MAX_BYTES])
def test_record_key_at_or_below_max_accepted(size):
    """Boundary check: the documented max must actually work."""
    rk = b"r" * size
    ct = encrypt(
        b"data",
        server_key=SERVER_KEY,
        client_key=CLIENT_KEY,
        record_key=rk,
    )
    assert (
        decrypt(ct, server_key=SERVER_KEY, client_key=CLIENT_KEY, record_key=rk)
        == b"data"
    )


# ---------------------------------------------------------------------------
# Single-shot size limit
# ---------------------------------------------------------------------------


def test_oversized_data_rejected_with_input_size_error():
    with pytest.raises(InputSizeError):
        encrypt(
            b"x" * (MAX_SINGLE_SHOT_SIZE_BYTES + 1),
            server_key=SERVER_KEY,
            client_key=CLIENT_KEY,
            record_key=RECORD_KEY,
        )


def test_oversized_ciphertext_rejected_with_input_size_error():
    """The bytes-API decrypt must reject oversized ciphertexts so an
    attacker cannot exhaust memory by submitting a multi-GB blob."""
    with pytest.raises(InputSizeError):
        decrypt(
            b"x" * (MAX_SINGLE_SHOT_CIPHERTEXT_BYTES + 1),
            server_key=SERVER_KEY,
            client_key=CLIENT_KEY,
            record_key=RECORD_KEY,
        )


def test_data_at_max_single_shot_size_accepted():
    """Boundary: exactly the max must succeed — only > max should fail."""
    payload = b"x" * MAX_SINGLE_SHOT_SIZE_BYTES
    ct = encrypt(
        payload,
        server_key=SERVER_KEY,
        client_key=CLIENT_KEY,
        record_key=RECORD_KEY,
    )
    assert (
        decrypt(
            ct,
            server_key=SERVER_KEY,
            client_key=CLIENT_KEY,
            record_key=RECORD_KEY,
        )
        == payload
    )


# ---------------------------------------------------------------------------
# Compression level validation
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("level", [-100, -1, ZSTD_MAX_LEVEL + 1, 100, 1000])
def test_invalid_compress_level_rejected(level):
    with pytest.raises(ValueError, match="compress_level"):
        encrypt(
            b"data",
            server_key=SERVER_KEY,
            client_key=CLIENT_KEY,
            record_key=RECORD_KEY,
            compress_level=level,
        )


@pytest.mark.parametrize("level", [0, 1, ZSTD_MAX_LEVEL])
def test_valid_compress_level_accepted(level):
    """Boundary: the documented endpoints must actually be valid."""
    ct = encrypt(
        b"data",
        server_key=SERVER_KEY,
        client_key=CLIENT_KEY,
        record_key=RECORD_KEY,
        compress_level=level,
    )
    assert (
        decrypt(
            ct,
            server_key=SERVER_KEY,
            client_key=CLIENT_KEY,
            record_key=RECORD_KEY,
        )
        == b"data"
    )
