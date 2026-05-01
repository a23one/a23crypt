"""Compression-layer tests.

Verifies:
  * Round-trip across every compression level boundary.
  * Compression actually reduces compressible data (else the feature is
    silently broken in a way the round-trip test wouldn't catch).
  * Random / incompressible data still round-trips even though it can't
    be shrunk.
  * The bomb cap on ``decompress_chunk`` fires *during* decompression,
    not after.
"""

# Standard Library Imports
import os

# External Imports
import pytest

# Project Imports
from a23crypt import decrypt, encrypt
from a23crypt.compression import compress_chunk, decompress_chunk
from a23crypt.constants import MAX_CHUNK_SIZE_BYTES, ZSTD_MAX_LEVEL
from a23crypt.errors import CompressionError

# Test Imports
from tests.conftest import CLIENT_KEY, RECORD_KEY, SERVER_KEY


def _encrypt(data: bytes, *, compress_level: int) -> bytes:
    return encrypt(
        data,
        server_key=SERVER_KEY,
        client_key=CLIENT_KEY,
        record_key=RECORD_KEY,
        compress_level=compress_level,
    )


def _decrypt(ct: bytes) -> bytes:
    return decrypt(
        ct,
        server_key=SERVER_KEY,
        client_key=CLIENT_KEY,
        record_key=RECORD_KEY,
    )


# ---------------------------------------------------------------------------
# Round-trip across every level
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("level", list(range(ZSTD_MAX_LEVEL + 1)))
def test_roundtrip_every_zstd_level(level):
    plaintext = b"compressible payload " * 5000
    assert _decrypt(_encrypt(plaintext, compress_level=level)) == plaintext


@pytest.mark.parametrize("level", [0, 1, 3, 22])
@pytest.mark.parametrize(
    "payload_factory",
    [
        lambda: b"",
        lambda: b"x",
        lambda: b"a" * 100,
        lambda: b"abc" * MAX_CHUNK_SIZE_BYTES,
        lambda: os.urandom(8192),
        lambda: os.urandom(2 * MAX_CHUNK_SIZE_BYTES + 73),
    ],
    ids=["empty", "tiny", "small-repeat", "multichunk-repeat", "random-8k", "random-multichunk"],
)
def test_roundtrip_levels_and_payloads(level, payload_factory):
    payload = payload_factory()
    assert _decrypt(_encrypt(payload, compress_level=level)) == payload


# ---------------------------------------------------------------------------
# Efficacy — compression must actually compress compressible data
# ---------------------------------------------------------------------------


def test_compression_reduces_compressible_data():
    plaintext = b"a" * 100_000
    ct_off = _encrypt(plaintext, compress_level=0)
    ct_on = _encrypt(plaintext, compress_level=22)
    # With max-level zstd on 100 KB of repeated bytes, ciphertext must be
    # dramatically smaller. Generous threshold: 95% reduction.
    assert len(ct_on) < len(ct_off) * 0.05, (
        f"compression ineffective: off={len(ct_off)} on={len(ct_on)}"
    )


def test_compression_does_not_meaningfully_grow_random_data():
    plaintext = os.urandom(64_000)
    ct_off = _encrypt(plaintext, compress_level=0)
    ct_on = _encrypt(plaintext, compress_level=3)
    # Random data can grow slightly under compression (header overhead),
    # but the growth ceiling should be small. 5% headroom is generous.
    growth_ratio = len(ct_on) / len(ct_off)
    assert growth_ratio <= 1.05, f"random data ballooned: ratio={growth_ratio}"


# ---------------------------------------------------------------------------
# Bomb cap — must fire during decompression, not after
# ---------------------------------------------------------------------------


def test_decompress_chunk_within_cap_succeeds():
    plaintext = b"\x00" * 500_000
    bomb = compress_chunk(plaintext, level=22)
    # Bomb is small (~ a few hundred bytes) but decompresses to 500 KB.
    assert len(bomb) < 1000
    assert decompress_chunk(bomb, max_output_size=500_000) == plaintext


def test_decompress_chunk_at_exact_cap_succeeds():
    plaintext = b"\x00" * 100_000
    bomb = compress_chunk(plaintext, level=22)
    assert decompress_chunk(bomb, max_output_size=100_000) == plaintext


def test_decompress_chunk_rejects_bomb_beyond_cap():
    """The whole point of the streaming-decompress fix: cap must fire
    during decompression, so a 1 MB bomb cannot allocate 1 MB before we
    notice."""
    plaintext = b"\x00" * 1_000_000
    bomb = compress_chunk(plaintext, level=22)
    with pytest.raises(CompressionError, match="exceed"):
        decompress_chunk(bomb, max_output_size=10_000)


@pytest.mark.parametrize("cap", [1, 100, 1_000, 99_999])
def test_decompress_chunk_rejects_at_various_caps(cap):
    plaintext = b"\x00" * 100_000
    bomb = compress_chunk(plaintext, level=22)
    with pytest.raises(CompressionError):
        decompress_chunk(bomb, max_output_size=cap)


def test_decompress_chunk_rejects_garbage():
    with pytest.raises(CompressionError):
        decompress_chunk(b"this is not zstd", max_output_size=1024)


def test_decompress_chunk_rejects_incomplete_zstd_frame():
    """Truncating a valid zstd frame must produce a precise
    'incomplete' error rather than the bomb-cap message."""
    valid = compress_chunk(b"some plaintext data " * 50, level=3)
    truncated = valid[: len(valid) - 5]  # drop trailer
    with pytest.raises(CompressionError, match="incomplete"):
        decompress_chunk(truncated, max_output_size=10_000)


def test_decompress_chunk_rejects_trailing_data():
    plaintext = b"hello"
    valid = compress_chunk(plaintext, level=3)
    with pytest.raises(CompressionError, match="trailing"):
        decompress_chunk(valid + b"junk", max_output_size=100)


def test_decompress_chunk_rejects_zero_or_negative_cap():
    with pytest.raises(ValueError):
        decompress_chunk(b"", max_output_size=0)
    with pytest.raises(ValueError):
        decompress_chunk(b"", max_output_size=-1)
