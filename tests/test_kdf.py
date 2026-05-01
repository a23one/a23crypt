"""Unit tests for the KDF helper."""

# External Imports
import pytest
from cryptography.hazmat.primitives import hashes

# Project Imports
from a23crypt.kdf import derive_subkey


# ---------------------------------------------------------------------------
# Determinism and independence
# ---------------------------------------------------------------------------


def test_derive_subkey_is_deterministic():
    a = derive_subkey(
        b"x" * 32, salt=b"salt", info=b"info", hash_alg=hashes.SHA256()
    )
    b = derive_subkey(
        b"x" * 32, salt=b"salt", info=b"info", hash_alg=hashes.SHA256()
    )
    assert a == b


_BASE_KWARGS = {
    "key_material": b"x" * 32,
    "salt": b"salt",
    "info": b"info",
    "hash_alg": hashes.SHA256(),
}


@pytest.mark.parametrize(
    "override",
    [
        {"key_material": b"y" * 32},
        {"salt": b"different"},
        {"info": b"different"},
        {"hash_alg": hashes.SHA512()},
    ],
    ids=["key", "salt", "info", "hash"],
)
def test_derive_subkey_different_inputs_produce_different_outputs(override):
    base = derive_subkey(**_BASE_KWARGS)
    other = derive_subkey(**{**_BASE_KWARGS, **override})
    assert other != base


@pytest.mark.parametrize("length", [16, 32, 48, 64])
def test_derive_subkey_respects_length(length):
    out = derive_subkey(
        b"x" * 32,
        salt=b"salt",
        info=b"info",
        hash_alg=hashes.SHA256(),
        length=length,
    )
    assert len(out) == length


# ---------------------------------------------------------------------------
# Input validation
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("size", [0, 1, 8, 15])
def test_derive_subkey_rejects_short_key_material(size):
    with pytest.raises(ValueError, match="at least 16 bytes"):
        derive_subkey(
            b"x" * size,
            salt=b"salt",
            info=b"info",
            hash_alg=hashes.SHA256(),
        )


def test_derive_subkey_rejects_empty_info():
    with pytest.raises(ValueError, match="non-empty"):
        derive_subkey(
            b"x" * 32,
            salt=b"salt",
            info=b"",
            hash_alg=hashes.SHA256(),
        )


def test_derive_subkey_accepts_empty_salt():
    """Empty salt is legal in HKDF (treated as zero-byte string)."""
    out = derive_subkey(
        b"x" * 32, salt=b"", info=b"info", hash_alg=hashes.SHA256()
    )
    assert len(out) == 32
