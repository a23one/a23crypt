"""Round-trip and API-parity tests.

Verifies the basic property: ``decrypt(encrypt(x)) == x`` across a
representative range of inputs and the equivalence of the bytes API and
the streaming API.
"""

# Standard Library Imports
import io
import os

# External Imports
import pytest

# Project Imports
from a23crypt import decrypt, decrypt_stream, encrypt, encrypt_stream
from a23crypt.constants import MAX_CHUNK_SIZE_BYTES

# Test Imports
from tests.conftest import CLIENT_KEY, RECORD_KEY, SERVER_KEY


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _encrypt(data: bytes, *, compress_level: int = 0) -> bytes:
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
# Round-trip — sizes
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "size",
    [
        0,
        1,
        2,
        15,
        16,
        17,
        100,
        1023,
        1024,
        4095,
        4096,
        MAX_CHUNK_SIZE_BYTES - 1,
        MAX_CHUNK_SIZE_BYTES,
        MAX_CHUNK_SIZE_BYTES + 1,
        2 * MAX_CHUNK_SIZE_BYTES,
        2 * MAX_CHUNK_SIZE_BYTES + 17,
        5 * MAX_CHUNK_SIZE_BYTES + 1023,
    ],
    ids=lambda n: f"size={n}",
)
def test_roundtrip_size(size):
    plaintext = bytes(i % 256 for i in range(size))
    assert _decrypt(_encrypt(plaintext)) == plaintext


# ---------------------------------------------------------------------------
# Round-trip — content patterns (catch byte-handling bugs at edges)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "payload",
    [
        b"",
        b"\x00",
        b"\xff",
        b"\x00" * 4096,
        b"\xff" * 4096,
        b"\x00\xff" * 2048,
        b"hello world",
        b"\x89PNG\r\n\x1a\n",  # PNG magic — stresses any byte-special handling
        "héllo wörld 你好".encode("utf-8"),
        os.urandom(8192),
        os.urandom(MAX_CHUNK_SIZE_BYTES + 73),
    ],
    ids=[
        "empty",
        "single-null",
        "single-ff",
        "many-nulls",
        "many-ffs",
        "alternating",
        "ascii",
        "png-magic",
        "utf8",
        "random-8k",
        "random-multichunk",
    ],
)
def test_roundtrip_content_patterns(payload):
    assert _decrypt(_encrypt(payload)) == payload


# ---------------------------------------------------------------------------
# API parity — bytes vs streaming
# ---------------------------------------------------------------------------


def test_stream_api_matches_bytes_api():
    plaintext = b"streaming test " * 5000

    src = io.BytesIO(plaintext)
    dst = io.BytesIO()
    encrypt_stream(
        src,
        dst,
        server_key=SERVER_KEY,
        client_key=CLIENT_KEY,
        record_key=RECORD_KEY,
        compress_level=3,
    )
    ct_stream = dst.getvalue()

    out_src = io.BytesIO(ct_stream)
    out_dst = io.BytesIO()
    decrypt_stream(
        out_src,
        out_dst,
        server_key=SERVER_KEY,
        client_key=CLIENT_KEY,
        record_key=RECORD_KEY,
    )
    assert out_dst.getvalue() == plaintext


def test_cross_api_compatibility():
    """Verify that ciphertexts produced by the stream API can be decrypted by the
    bytes API, and vice-versa. This ensures the wire format is strictly identical."""
    plaintext = b"cross api compatibility test " * 1000

    # Stream encrypt -> Bytes decrypt
    src = io.BytesIO(plaintext)
    dst = io.BytesIO()
    encrypt_stream(
        src,
        dst,
        server_key=SERVER_KEY,
        client_key=CLIENT_KEY,
        record_key=RECORD_KEY,
        compress_level=3,
    )
    ct_stream = dst.getvalue()
    assert _decrypt(ct_stream) == plaintext

    # Bytes encrypt -> Stream decrypt
    ct_bytes = _encrypt(plaintext, compress_level=3)
    out_src = io.BytesIO(ct_bytes)
    out_dst = io.BytesIO()
    decrypt_stream(
        out_src,
        out_dst,
        server_key=SERVER_KEY,
        client_key=CLIENT_KEY,
        record_key=RECORD_KEY,
    )
    assert out_dst.getvalue() == plaintext


def test_real_file_roundtrip(tmp_path):
    plaintext = bytes(i % 256 for i in range(2 * MAX_CHUNK_SIZE_BYTES + 123))
    src_path = tmp_path / "in.bin"
    enc_path = tmp_path / "in.enc"
    dec_path = tmp_path / "out.bin"
    src_path.write_bytes(plaintext)

    with open(src_path, "rb") as src, open(enc_path, "wb") as dst:
        encrypt_stream(
            src,
            dst,
            server_key=SERVER_KEY,
            client_key=CLIENT_KEY,
            record_key=RECORD_KEY,
            compress_level=3,
        )

    with open(enc_path, "rb") as src, open(dec_path, "wb") as dst:
        decrypt_stream(
            src,
            dst,
            server_key=SERVER_KEY,
            client_key=CLIENT_KEY,
            record_key=RECORD_KEY,
        )

    assert dec_path.read_bytes() == plaintext
