"""Encrypt and decrypt entry points (single-shot and streaming).

See README for format spec, security properties, and usage notes.
"""

import io
import os
import struct
from typing import BinaryIO

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305

from a23crypt.compression import compress_chunk, decompress_chunk
from a23crypt.constants import (
    CONTEXT_MAX_BYTES,
    KEY_SIZE_BYTES,
    MAX_CHUNK_SIZE_BYTES,
    MAX_SINGLE_SHOT_CIPHERTEXT_BYTES,
    MAX_SINGLE_SHOT_SIZE_BYTES,
    NOISE_SEED_SIZE_BYTES,
    SALT_SIZE_BYTES,
    ZSTD_MAX_LEVEL,
)
from a23crypt.errors import (
    CompressionError,
    DecryptionError,
    InputSizeError,
    IntegrityError,
    InvalidKeyError,
)
from a23crypt.kdf import derive_subkey
from a23crypt.noise import add_noise, remove_noise
from a23crypt.streaming import iter_chunks_with_final, iter_frames_with_final


# Single source of truth for the wire-format version. Bump this one
# integer to roll the format; the version byte and HKDF info labels
# below all derive from it.
_FORMAT_VERSION: int = 1
_VERSION_BYTE: bytes = _FORMAT_VERSION.to_bytes(1, "big")
_INFO_PREFIX: bytes = f"a23crypt-v{_FORMAT_VERSION}".encode("ascii")
_INFO_SERVER: bytes = _INFO_PREFIX + b"-server-stream"
_INFO_CLIENT: bytes = _INFO_PREFIX + b"-client-stream"
_INFO_NOISE: bytes = _INFO_PREFIX + b"-noise-seed"

# AAD per chunk: chunk_index (Q) | is_final (?) | flags (B) | chunk_size (I).
_AAD_FMT: str = ">Q?BI"

_NONCE_DOMAIN_INNER: int = 0
_NONCE_DOMAIN_OUTER: int = 1

# Bits 0-4 of flags byte hold the zstd level; bits 5-7 reserved.
_COMPRESS_LEVEL_MASK: int = 0b00011111


def _validate_inputs(
    server_key: bytes,
    client_key: bytes,
    record_key: bytes,
) -> None:
    if len(server_key) != KEY_SIZE_BYTES:
        raise InvalidKeyError(f"server_key must be {KEY_SIZE_BYTES} bytes")
    if len(client_key) != KEY_SIZE_BYTES:
        raise InvalidKeyError(f"client_key must be {KEY_SIZE_BYTES} bytes")
    if len(record_key) == 0:
        raise InvalidKeyError("record_key must not be empty")
    if len(record_key) > CONTEXT_MAX_BYTES:
        raise InvalidKeyError(
            f"record_key must be ≤ {CONTEXT_MAX_BYTES} bytes, "
            f"got {len(record_key)}"
        )


def _derive_record_subkeys(
    server_key: bytes,
    client_key: bytes,
    record_key: bytes,
    salt: bytes,
) -> tuple[bytes, bytes]:
    """Derive (server_sub, client_sub) via HKDF.

    HKDF salt = record_key + per-encryption random salt. Per-record
    diversification (record_key) and per-encryption diversification
    (salt) are both bound into the derivation, so two encryptions
    under the same record_key get cryptographically independent subkeys.
    Mixed hash families (SHA-2 inner, SHA-3 outer) are intentional.
    """
    hkdf_salt = record_key + salt
    server_sub = derive_subkey(
        server_key,
        salt=hkdf_salt,
        info=_INFO_SERVER,
        hash_alg=hashes.SHA512(),
    )
    client_sub = derive_subkey(
        client_key,
        salt=hkdf_salt,
        info=_INFO_CLIENT,
        hash_alg=hashes.SHA3_512(),
    )
    return server_sub, client_sub


def _derive_chunk_noise_seed(
    server_key: bytes,
    client_key: bytes,
    record_key: bytes,
    hkdf_salt: bytes,
    chunk_index: int,
) -> bytes:
    """Derive the per-chunk noise seed via HKDF.

    The seed depends on both master keys plus the per-record /
    per-encryption / per-chunk salt material. An attacker who breaks
    the outer AEAD still cannot compute the seed without recovering
    at least one master key — the seed never appears on the wire.
    """
    return derive_subkey(
        server_key + client_key,
        salt=record_key + hkdf_salt + struct.pack(">Q", chunk_index),
        info=_INFO_NOISE,
        hash_alg=hashes.SHA256(),
        length=NOISE_SEED_SIZE_BYTES,
    )


def _read_exact(src: BinaryIO, n: int, field_name: str) -> bytes:
    data = src.read(n)
    if len(data) < n:
        raise IntegrityError(f"truncated header ({field_name})")
    return data


def _read_header(
    src: BinaryIO, expected_record_key: bytes
) -> tuple[int, int, bytes]:
    """Read and validate the format header. Returns (flags, chunk_size, salt)."""
    version = _read_exact(src, 1, "version")
    if version != _VERSION_BYTE:
        raise IntegrityError(f"unsupported format version: {version!r}")

    flags = _read_exact(src, 1, "flags")[0]
    (chunk_size,) = struct.unpack(">I", _read_exact(src, 4, "chunk_size"))

    (rk_len,) = struct.unpack(">I", _read_exact(src, 4, "record_key length"))
    if rk_len > CONTEXT_MAX_BYTES:
        raise IntegrityError(f"record_key length {rk_len} exceeds limit")

    stored_record_key = _read_exact(src, rk_len, "record_key body")
    if stored_record_key != expected_record_key:
        raise IntegrityError("record_key mismatch")

    salt = _read_exact(src, SALT_SIZE_BYTES, "salt")

    return flags, chunk_size, salt


def encrypt_stream(
    src: BinaryIO,
    dst: BinaryIO,
    *,
    server_key: bytes,
    client_key: bytes,
    record_key: bytes,
    compress_level: int = 0,
) -> None:
    """Encrypt a binary stream with constant memory.

    Args:
        src: Readable binary stream of plaintext. Wrap network sources
            in `io.BufferedReader` to avoid sub-optimal chunking on
            short reads.
        dst: Writable binary stream for ciphertext.
        server_key: 32-byte server-held key.
        client_key: 32-byte client-held key.
        record_key: 1 to `CONTEXT_MAX_BYTES` bytes of record context.
        compress_level: zstd level. 0 disables compression. Range 1-22.

    Raises:
        InvalidKeyError: Key wrong size, or record_key empty / oversized.
        ValueError: `compress_level` outside 0-22.

    A fresh random salt is generated per encryption and stored in the
    header. Two encryptions of the same plaintext under the same keys
    produce different ciphertexts. Reusing `record_key` is safe — each
    encryption derives independent subkeys via the per-encryption salt.
    """
    _validate_inputs(server_key, client_key, record_key)
    if not 0 <= compress_level <= ZSTD_MAX_LEVEL:
        raise ValueError(
            f"compress_level must be 0-{ZSTD_MAX_LEVEL}, got {compress_level}"
        )

    to_compress = compress_level > 0
    salt = os.urandom(SALT_SIZE_BYTES)
    server_sub, client_sub = _derive_record_subkeys(
        server_key, client_key, record_key, salt
    )
    inner_aead = AESGCM(server_sub)
    outer_aead = ChaCha20Poly1305(client_sub)

    flags = compress_level & _COMPRESS_LEVEL_MASK
    chunk_size = MAX_CHUNK_SIZE_BYTES

    dst.write(_VERSION_BYTE)
    dst.write(bytes([flags]))
    dst.write(struct.pack(">I", chunk_size))
    dst.write(struct.pack(">I", len(record_key)))
    dst.write(record_key)
    dst.write(salt)

    for chunk_index, (chunk, is_final) in enumerate(iter_chunks_with_final(src)):
        plaintext = (
            compress_chunk(chunk, level=compress_level) if to_compress else chunk
        )
        aad = struct.pack(_AAD_FMT, chunk_index, is_final, flags, chunk_size)

        inner_nonce = struct.pack(">QI", chunk_index, _NONCE_DOMAIN_INNER)
        inner_ct = inner_aead.encrypt(inner_nonce, plaintext, aad)

        # Per-chunk noise seed: HKDF-derived from both master keys plus
        # per-record / per-encryption / per-chunk salt material. Never
        # appears on the wire.
        noise_seed = _derive_chunk_noise_seed(
            server_key, client_key, record_key, salt, chunk_index
        )
        noisy = add_noise(inner_ct, noise_seed)

        outer_nonce = struct.pack(">QI", chunk_index, _NONCE_DOMAIN_OUTER)
        outer_ct = outer_aead.encrypt(outer_nonce, noisy, aad)

        dst.write(struct.pack(">I", len(outer_ct)))
        dst.write(outer_ct)


def decrypt_stream(
    src: BinaryIO,
    dst: BinaryIO,
    *,
    server_key: bytes,
    client_key: bytes,
    record_key: bytes,
) -> None:
    """Decrypt a binary stream produced by `encrypt_stream`.

    Args:
        src: Readable binary stream of ciphertext. Must return full
            reads up to EOF (regular files, `BytesIO`). Wrap network
            sockets, pipes, or any source that may return short reads
            in `io.BufferedReader` — otherwise legitimate slow streams
            will surface as `IntegrityError` (truncated frame/header).
        dst: Writable binary stream for plaintext.
        server_key: 32-byte server key (must match encryption).
        client_key: 32-byte client key (must match encryption).
        record_key: Record key (must match encryption).

    Raises:
        IntegrityError: Format-level failure (truncation, malformed
            header, oversized fields, record_key mismatch, missing final
            chunk marker).
        DecryptionError: Cryptographic failure (wrong key, tampered
            ciphertext). Message uniform; full diagnostic via `__cause__`.

    On exception, `dst` may contain partial output from chunks before
    the failure. For atomic semantics, use the bytes-API `decrypt` or
    buffer via `BytesIO`.
    """
    _validate_inputs(server_key, client_key, record_key)

    flags, chunk_size, salt = _read_header(src, expected_record_key=record_key)
    compress_level = flags & _COMPRESS_LEVEL_MASK
    to_decompress = compress_level > 0

    server_sub, client_sub = _derive_record_subkeys(
        server_key, client_key, record_key, salt
    )
    inner_aead = AESGCM(server_sub)
    outer_aead = ChaCha20Poly1305(client_sub)

    saw_final = False
    for chunk_index, (frame, is_final) in enumerate(iter_frames_with_final(src)):
        aad = struct.pack(_AAD_FMT, chunk_index, is_final, flags, chunk_size)
        try:
            outer_nonce = struct.pack(">QI", chunk_index, _NONCE_DOMAIN_OUTER)
            noisy = outer_aead.decrypt(outer_nonce, frame, aad)

            # Re-derive the per-chunk noise seed from secret material.
            noise_seed = _derive_chunk_noise_seed(
                server_key, client_key, record_key, salt, chunk_index
            )
            inner_ct = remove_noise(noisy, noise_seed)

            inner_nonce = struct.pack(">QI", chunk_index, _NONCE_DOMAIN_INNER)
            plaintext = inner_aead.decrypt(inner_nonce, inner_ct, aad)

            if to_decompress:
                plaintext = decompress_chunk(
                    plaintext, max_output_size=chunk_size
                )
        except (InvalidTag, CompressionError) as e:
            raise DecryptionError("decryption failed") from e

        if is_final:
            saw_final = True
        dst.write(plaintext)

    if not saw_final:
        raise IntegrityError(
            "ciphertext contained no final chunk (possible truncation)"
        )


def encrypt(
    data: bytes,
    *,
    server_key: bytes,
    client_key: bytes,
    record_key: bytes,
    compress_level: int = 0,
) -> bytes:
    """Encrypt a bytes blob (≤ `MAX_SINGLE_SHOT_SIZE_BYTES`).

    For larger inputs, use `encrypt_stream`. Each call uses a fresh
    random salt — same plaintext under same keys produces different
    ciphertexts each call.

    Raises:
        InputSizeError: `data` exceeds `MAX_SINGLE_SHOT_SIZE_BYTES`.
        InvalidKeyError: Key wrong size, or record_key empty / oversized.
        ValueError: `compress_level` outside 0-22.
    """
    if len(data) > MAX_SINGLE_SHOT_SIZE_BYTES:
        raise InputSizeError(
            f"data exceeds {MAX_SINGLE_SHOT_SIZE_BYTES} bytes; "
            f"use encrypt_stream"
        )
    src = io.BytesIO(data)
    dst = io.BytesIO()
    encrypt_stream(
        src,
        dst,
        server_key=server_key,
        client_key=client_key,
        record_key=record_key,
        compress_level=compress_level,
    )
    return dst.getvalue()


def decrypt(
    ciphertext: bytes,
    *,
    server_key: bytes,
    client_key: bytes,
    record_key: bytes,
) -> bytes:
    """Decrypt a bytes blob produced by `encrypt`. Atomic on success.

    Raises ``InputSizeError`` if ``ciphertext`` exceeds
    ``MAX_SINGLE_SHOT_CIPHERTEXT_BYTES``; larger inputs must use
    ``decrypt_stream`` so memory stays bounded per chunk.
    """
    if len(ciphertext) > MAX_SINGLE_SHOT_CIPHERTEXT_BYTES:
        raise InputSizeError(
            f"ciphertext exceeds {MAX_SINGLE_SHOT_CIPHERTEXT_BYTES} bytes; "
            f"use decrypt_stream"
        )
    src = io.BytesIO(ciphertext)
    dst = io.BytesIO()
    decrypt_stream(
        src,
        dst,
        server_key=server_key,
        client_key=client_key,
        record_key=record_key,
    )
    return dst.getvalue()
