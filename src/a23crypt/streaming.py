"""Streaming helpers: chunk and frame iterators."""

import struct
from typing import BinaryIO, Iterator

from a23crypt.constants import MAX_CHUNK_SIZE_BYTES
from a23crypt.errors import IntegrityError


# Reject frame bodies above 2× chunk size — generous room for AEAD tag
# and noise expansion, but tight enough that a malformed length prefix
# cannot trigger a memory blow-up before AEAD verification.
_MAX_FRAME_BODY_BYTES: int = 2 * MAX_CHUNK_SIZE_BYTES


def iter_chunks_with_final(
    src: BinaryIO,
    chunk_size: int = MAX_CHUNK_SIZE_BYTES,
) -> Iterator[tuple[bytes, bool]]:
    """Yield (chunk, is_final) pairs from a binary stream.

    Always yields at least one pair. Empty source yields a single
    `(b"", True)` so the format cannot be silently truncated to header.
    """
    current = src.read(chunk_size)
    if not current:
        yield b"", True
        return

    while current:
        next_chunk = src.read(chunk_size)
        is_final = len(next_chunk) == 0
        yield current, is_final
        current = next_chunk


def iter_frames_with_final(src: BinaryIO) -> Iterator[tuple[bytes, bool]]:
    """Yield (frame_bytes, is_final) from a length-prefixed framed stream.

    Yields nothing for an empty source. Callers must verify they saw a
    frame with `is_final=True`; otherwise the stream was truncated.
    """
    current = _read_frame(src)
    while current is not None:
        next_frame = _read_frame(src)
        is_final = next_frame is None
        yield current, is_final
        current = next_frame


def _read_frame(src: BinaryIO) -> bytes | None:
    """Read [4-byte length][body]. Return None on clean EOF."""
    length_bytes = src.read(4)
    if len(length_bytes) == 0:
        return None
    if len(length_bytes) < 4:
        raise IntegrityError("truncated frame header")
    (length,) = struct.unpack(">I", length_bytes)
    if length > _MAX_FRAME_BODY_BYTES:
        raise IntegrityError(
            f"frame length {length} exceeds limit {_MAX_FRAME_BODY_BYTES}"
        )
    body = src.read(length)
    if len(body) < length:
        raise IntegrityError("truncated frame body")
    return body
