"""Adversarial / security tests.

Covers:
  * Truncation defenses (header-only, mid-stream, partial frame).
  * Tampering defenses (bit flips at every region of the ciphertext).
  * Frame-level attacks (reorder, duplicate, substitute across records).
  * DoS defenses (oversized length prefixes, oversized header fields).
  * Wrong-key detection.
  * Per-record cryptographic isolation.

These tests are the security-correctness contract of the format. A
regression in any of them indicates a real exploitable defect, not a
style or polish issue.
"""

# Standard Library Imports
import struct

# External Imports
import pytest

# Project Imports
from a23crypt import decrypt, encrypt
from a23crypt.constants import MAX_CHUNK_SIZE_BYTES, SALT_SIZE_BYTES
from a23crypt.errors import DecryptionError, IntegrityError

# Test Imports
from tests.conftest import (
    ALT_CLIENT_KEY,
    ALT_RECORD_KEY,
    ALT_SERVER_KEY,
    CLIENT_KEY,
    RECORD_KEY,
    SERVER_KEY,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _encrypt(
    data: bytes,
    *,
    record_key: bytes = RECORD_KEY,
    server_key: bytes = SERVER_KEY,
    client_key: bytes = CLIENT_KEY,
    compress_level: int = 0,
) -> bytes:
    return encrypt(
        data,
        server_key=server_key,
        client_key=client_key,
        record_key=record_key,
        compress_level=compress_level,
    )


def _decrypt(
    ct: bytes,
    *,
    record_key: bytes = RECORD_KEY,
    server_key: bytes = SERVER_KEY,
    client_key: bytes = CLIENT_KEY,
) -> bytes:
    return decrypt(
        ct,
        server_key=server_key,
        client_key=client_key,
        record_key=record_key,
    )


def _header_length(record_key: bytes = RECORD_KEY) -> int:
    """Layout: version(1) + flags(1) + chunk_size(4) + rk_len(4) + record_key + salt."""
    return 1 + 1 + 4 + 4 + len(record_key) + SALT_SIZE_BYTES


def _split_into_frames(ct: bytes, record_key: bytes = RECORD_KEY) -> tuple[bytes, list[bytes]]:
    """Return (header_bytes, list_of_frame_bytes_with_length_prefix)."""
    header_len = _header_length(record_key)
    header = ct[:header_len]
    frames: list[bytes] = []
    pos = header_len
    while pos < len(ct):
        (length,) = struct.unpack(">I", ct[pos : pos + 4])
        frames.append(ct[pos : pos + 4 + length])
        pos += 4 + length
    return header, frames


# ---------------------------------------------------------------------------
# Truncation defenses
# ---------------------------------------------------------------------------


def test_truncation_to_header_only_rejected():
    """Truncating non-empty ciphertext to its header must be detected."""
    ct = _encrypt(b"important data " * 100)
    header_only = ct[: _header_length()]
    with pytest.raises(IntegrityError, match="no final chunk"):
        _decrypt(header_only)


def test_truncation_drops_last_frame_rejected():
    """Removing the last frame from a multi-chunk ciphertext must fail —
    the new last frame's AAD has is_final=True at decrypt but was
    authenticated with is_final=False at encrypt."""
    plaintext = b"abc" * MAX_CHUNK_SIZE_BYTES  # multi-chunk
    ct = _encrypt(plaintext)
    header, frames = _split_into_frames(ct)
    assert len(frames) >= 2, "test requires multi-chunk ciphertext"
    truncated = header + b"".join(frames[:-1])
    with pytest.raises((DecryptionError, IntegrityError)):
        _decrypt(truncated)


def test_truncation_drops_multiple_trailing_frames_rejected():
    plaintext = b"abc" * (4 * MAX_CHUNK_SIZE_BYTES)
    ct = _encrypt(plaintext)
    header, frames = _split_into_frames(ct)
    assert len(frames) >= 4
    truncated = header + b"".join(frames[:2])
    with pytest.raises((DecryptionError, IntegrityError)):
        _decrypt(truncated)


@pytest.mark.parametrize(
    "fraction",
    [0.0, 0.05, 0.10, 0.25, 0.5, 0.75, 0.95, 0.99],
    ids=lambda f: f"keep={int(f*100)}%",
)
def test_truncation_at_arbitrary_byte_offset_rejected(fraction):
    """Truncating to *any* byte offset less than the full ciphertext
    must produce an error, never a silently-different plaintext."""
    plaintext = b"x" * 50_000
    ct = _encrypt(plaintext, compress_level=3)
    cut = int(len(ct) * fraction)
    if cut == len(ct):
        pytest.skip("not actually truncated")
    truncated = ct[:cut]
    with pytest.raises((DecryptionError, IntegrityError)):
        _decrypt(truncated)


# ---------------------------------------------------------------------------
# Bit-flip / tampering defenses
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "offset",
    [0, 1, 2, 5, 9, 15, 20, 50, 100, 200, 500, 1000, -50, -10, -1],
    ids=lambda o: f"offset={o}",
)
def test_bit_flip_at_various_positions_rejected(offset):
    """A single-bit flip anywhere in a valid ciphertext must be detected."""
    ct = bytearray(_encrypt(b"hello world " * 200))
    if abs(offset) >= len(ct):
        pytest.skip(f"offset {offset} out of range")
    ct[offset] ^= 0x01
    with pytest.raises((DecryptionError, IntegrityError)):
        _decrypt(bytes(ct))


def test_zero_byte_replacement_in_body_rejected():
    """Replacing a body byte with 0 (rather than xor-flipping) must also
    be detected — this catches any 'trust if value is zero' bug."""
    ct = bytearray(_encrypt(b"hello world " * 100))
    body_offset = _header_length() + 4 + 5  # past length prefix into body
    ct[body_offset] = 0
    with pytest.raises((DecryptionError, IntegrityError)):
        _decrypt(bytes(ct))


def test_appending_garbage_rejected():
    """Concatenating extra bytes to a valid ciphertext must be detected
    (otherwise an attacker can extend the stream)."""
    ct = _encrypt(b"hello") + b"junk-extra-frame-prefix-here"
    with pytest.raises((DecryptionError, IntegrityError)):
        _decrypt(ct)


# ---------------------------------------------------------------------------
# Header-field tampering (every field bound by AAD must be detected)
# ---------------------------------------------------------------------------


def test_tampered_version_byte_rejected():
    ct = bytearray(_encrypt(b"data"))
    ct[0] = 0xFF  # any non-current-version byte
    with pytest.raises(IntegrityError, match="version"):
        _decrypt(bytes(ct))


def test_tampered_flags_byte_rejected():
    """Flags byte is in AAD — flipping it must fail AEAD verification."""
    ct = bytearray(_encrypt(b"data"))
    ct[1] ^= 0x01  # toggle low bit (compress flag)
    with pytest.raises((DecryptionError, IntegrityError)):
        _decrypt(bytes(ct))


def test_tampered_chunk_size_in_header_rejected():
    """chunk_size is bound into AAD."""
    ct = bytearray(_encrypt(b"hello"))
    ct[2:6] = struct.pack(">I", MAX_CHUNK_SIZE_BYTES * 2)
    with pytest.raises((DecryptionError, IntegrityError)):
        _decrypt(bytes(ct))


def test_tampered_record_key_length_rejected():
    """rk_len mismatch causes either truncated-header or record_key
    mismatch — both must be detected."""
    ct = bytearray(_encrypt(b"hello"))
    ct[6:10] = struct.pack(">I", len(RECORD_KEY) + 5)  # claim longer rk
    with pytest.raises((DecryptionError, IntegrityError)):
        _decrypt(bytes(ct))


def test_tampered_record_key_body_rejected():
    """Modifying record_key bytes in the header must fail (mismatch with
    the record_key supplied to decrypt)."""
    ct = bytearray(_encrypt(b"hello"))
    rk_offset = 1 + 1 + 4 + 4
    ct[rk_offset] ^= 0xFF
    with pytest.raises(IntegrityError, match="record_key"):
        _decrypt(bytes(ct))


# ---------------------------------------------------------------------------
# Frame-level attacks
# ---------------------------------------------------------------------------


def test_frame_reorder_rejected():
    """Swapping two frames must fail — chunk_index in AAD ties each frame
    to its original position."""
    plaintext = b"x" * (3 * MAX_CHUNK_SIZE_BYTES + 17)
    ct = _encrypt(plaintext)
    header, frames = _split_into_frames(ct)
    assert len(frames) >= 3
    # Swap frame 0 and frame 1
    reordered = header + frames[1] + frames[0] + b"".join(frames[2:])
    with pytest.raises((DecryptionError, IntegrityError)):
        _decrypt(reordered)


def test_frame_duplication_rejected():
    """Replacing frame 1 with a copy of frame 0 must fail (chunk_index
    AAD mismatch on the duplicate)."""
    plaintext = b"x" * (3 * MAX_CHUNK_SIZE_BYTES + 17)
    ct = _encrypt(plaintext)
    header, frames = _split_into_frames(ct)
    assert len(frames) >= 2
    duplicated = header + frames[0] + frames[0] + b"".join(frames[2:])
    with pytest.raises((DecryptionError, IntegrityError)):
        _decrypt(duplicated)


def test_frame_substitution_from_other_record_rejected():
    """A frame from record A pasted into record B's ciphertext must fail
    — record_key drives the HKDF subkeys, so cross-record frames decrypt
    to nothing meaningful."""
    plaintext = b"x" * (2 * MAX_CHUNK_SIZE_BYTES + 17)
    ct_a = _encrypt(plaintext, record_key=RECORD_KEY)
    ct_b = _encrypt(plaintext, record_key=ALT_RECORD_KEY)

    header_b, frames_b = _split_into_frames(ct_b, record_key=ALT_RECORD_KEY)
    _, frames_a = _split_into_frames(ct_a)

    # Replace frame 0 of B's ciphertext with frame 0 of A's.
    swapped = header_b + frames_a[0] + b"".join(frames_b[1:])
    with pytest.raises((DecryptionError, IntegrityError)):
        _decrypt(swapped, record_key=ALT_RECORD_KEY)


def test_frame_substitution_from_same_record_different_position_rejected():
    """Even within the same record, a frame from position N pasted at
    position M must fail (chunk_index AAD)."""
    plaintext = b"x" * (3 * MAX_CHUNK_SIZE_BYTES + 17)
    ct = _encrypt(plaintext)
    header, frames = _split_into_frames(ct)
    assert len(frames) >= 3
    # Put frame[2] in position 0
    swapped = header + frames[2] + b"".join(frames[1:])
    with pytest.raises((DecryptionError, IntegrityError)):
        _decrypt(swapped)


# ---------------------------------------------------------------------------
# DoS defenses — oversized claimed sizes
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "claimed_length",
    [
        2 * MAX_CHUNK_SIZE_BYTES + 1,  # one byte over the cap
        4 * MAX_CHUNK_SIZE_BYTES,
        1 << 20,                        # 1 MB
        1 << 30,                        # 1 GB
        (1 << 32) - 1,                  # uint32 max
    ],
    ids=lambda n: f"len={n}",
)
def test_oversized_frame_length_prefix_rejected(claimed_length):
    """Any frame length prefix beyond the configured cap must be rejected
    before any large allocation."""
    header_len = _header_length()
    ct = _encrypt(b"hi")
    forged = ct[:header_len] + struct.pack(">I", claimed_length) + b"x" * 16
    with pytest.raises(IntegrityError, match="exceeds limit"):
        _decrypt(forged)


def test_oversized_record_key_length_in_header_rejected():
    """rk_len > CONTEXT_MAX_BYTES must be rejected at header parse."""
    forged = (
        b"\x01"                      # current version
        + b"\x00"                    # flags
        + struct.pack(">I", MAX_CHUNK_SIZE_BYTES)
        + struct.pack(">I", 1 << 24)  # claim 16 MB record_key
        + RECORD_KEY
        + b"\x00" * SALT_SIZE_BYTES
    )
    with pytest.raises(IntegrityError, match="exceeds limit"):
        _decrypt(forged)


@pytest.mark.parametrize(
    "extra",
    [1, 2, 3],
    ids=lambda n: f"frame_prefix_bytes={n}",
)
def test_truncated_frame_header_rejected(extra):
    """A complete header followed by 1-3 bytes of frame length prefix
    must surface as IntegrityError('truncated frame header')."""
    ct = _encrypt(b"data")
    truncated = ct[: _header_length() + extra]
    with pytest.raises(IntegrityError, match="truncated frame header"):
        _decrypt(truncated)


@pytest.mark.parametrize(
    "cut",
    list(range(0, _header_length())),
    ids=lambda n: f"cut={n}",
)
def test_truncated_header_at_byte_offset_rejected(cut):
    """Cutting the ciphertext anywhere within the fixed-length header
    must produce IntegrityError, with the failure point self-identifying
    in test output."""
    ct = _encrypt(b"data")
    with pytest.raises(IntegrityError):
        _decrypt(ct[:cut])


# ---------------------------------------------------------------------------
# Wrong-key defenses
# ---------------------------------------------------------------------------


def test_wrong_server_key_rejected():
    ct = _encrypt(b"secret")
    with pytest.raises(DecryptionError):
        _decrypt(ct, server_key=ALT_SERVER_KEY)


def test_wrong_client_key_rejected():
    ct = _encrypt(b"secret")
    with pytest.raises(DecryptionError):
        _decrypt(ct, client_key=ALT_CLIENT_KEY)


def test_wrong_record_key_rejected():
    ct = _encrypt(b"secret")
    with pytest.raises(IntegrityError, match="record_key mismatch"):
        _decrypt(ct, record_key=ALT_RECORD_KEY)


def test_all_wrong_keys_rejected():
    ct = _encrypt(b"secret")
    with pytest.raises((DecryptionError, IntegrityError)):
        _decrypt(
            ct,
            server_key=ALT_SERVER_KEY,
            client_key=ALT_CLIENT_KEY,
            record_key=ALT_RECORD_KEY,
        )


# ---------------------------------------------------------------------------
# Cryptographic isolation
# ---------------------------------------------------------------------------


def test_different_record_keys_produce_different_ciphertexts():
    """Same plaintext, different record_key → different ciphertext bodies.
    Confirms per-record key diversification is wired up correctly."""
    plaintext = b"the same plaintext"
    ct_a = _encrypt(plaintext, record_key=RECORD_KEY)
    ct_b = _encrypt(plaintext, record_key=ALT_RECORD_KEY)
    # Strip headers (which include the record_key bytes) before comparing
    # the actual encrypted bodies.
    _, frames_a = _split_into_frames(ct_a, record_key=RECORD_KEY)
    _, frames_b = _split_into_frames(ct_b, record_key=ALT_RECORD_KEY)
    assert frames_a != frames_b


def test_different_server_keys_produce_different_ciphertexts():
    plaintext = b"the same plaintext"
    ct_a = _encrypt(plaintext)
    ct_b = _encrypt(plaintext, server_key=ALT_SERVER_KEY)
    _, frames_a = _split_into_frames(ct_a)
    _, frames_b = _split_into_frames(ct_b)
    assert frames_a != frames_b


def test_different_client_keys_produce_different_ciphertexts():
    plaintext = b"the same plaintext"
    ct_a = _encrypt(plaintext)
    ct_b = _encrypt(plaintext, client_key=ALT_CLIENT_KEY)
    _, frames_a = _split_into_frames(ct_a)
    _, frames_b = _split_into_frames(ct_b)
    assert frames_a != frames_b


def test_repeat_encryption_is_non_deterministic():
    """Two encryptions of the same plaintext under identical keys and
    record_key MUST produce different ciphertexts. The per-encryption
    random salt eliminates the AES-GCM/ChaCha20Poly1305 nonce-reuse
    foot-gun that a deterministic format would expose."""
    plaintext = b"identical plaintext under identical keys"
    ct1 = _encrypt(plaintext)
    ct2 = _encrypt(plaintext)
    assert ct1 != ct2

    # Both must still decrypt correctly to the original plaintext.
    assert _decrypt(ct1) == plaintext
    assert _decrypt(ct2) == plaintext
