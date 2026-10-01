"""Unit tests for streaming helpers."""

# Standard Library Imports
import io
import struct

# External Imports
import pytest

# Project Imports
from a23crypt.errors import IntegrityError
from a23crypt.streaming import (
    iter_chunks_with_final,
    iter_frames_with_final,
    _MAX_FRAME_BODY_BYTES,
)


# ---------------------------------------------------------------------------
# iter_chunks_with_final
# ---------------------------------------------------------------------------


def test_iter_chunks_empty_stream():
    src = io.BytesIO(b"")
    chunks = list(iter_chunks_with_final(src))
    assert chunks == [(b"", True)]


def test_iter_chunks_single_chunk():
    src = io.BytesIO(b"hello")
    chunks = list(iter_chunks_with_final(src, chunk_size=10))
    assert chunks == [(b"hello", True)]


def test_iter_chunks_exact_chunk_boundary():
    src = io.BytesIO(b"hello")
    chunks = list(iter_chunks_with_final(src, chunk_size=5))
    # It reads exactly 5 bytes, then next read returns empty, so it knows it is final.
    assert chunks == [(b"hello", True)]


def test_iter_chunks_multi_chunk():
    src = io.BytesIO(b"helloworld")
    chunks = list(iter_chunks_with_final(src, chunk_size=4))
    assert chunks == [
        (b"hell", False),
        (b"owor", False),
        (b"ld", True),
    ]


# ---------------------------------------------------------------------------
# iter_frames_with_final
# ---------------------------------------------------------------------------


def test_iter_frames_empty_stream():
    src = io.BytesIO(b"")
    frames = list(iter_frames_with_final(src))
    assert frames == []


def test_iter_frames_single_frame():
    frame_body = b"hello"
    data = struct.pack(">I", len(frame_body)) + frame_body
    src = io.BytesIO(data)
    frames = list(iter_frames_with_final(src))
    assert frames == [(b"hello", True)]


def test_iter_frames_multi_frame():
    f1 = b"hello"
    f2 = b"world"
    data = struct.pack(">I", len(f1)) + f1 + struct.pack(">I", len(f2)) + f2
    src = io.BytesIO(data)
    frames = list(iter_frames_with_final(src))
    assert frames == [
        (b"hello", False),
        (b"world", True),
    ]


def test_iter_frames_truncated_header():
    src = io.BytesIO(b"\x00\x00")  # Only 2 bytes, needs 4
    with pytest.raises(IntegrityError, match="truncated frame header"):
        list(iter_frames_with_final(src))


def test_iter_frames_oversized_frame():
    too_big = _MAX_FRAME_BODY_BYTES + 1
    src = io.BytesIO(struct.pack(">I", too_big) + b"xyz")
    with pytest.raises(IntegrityError, match="exceeds limit"):
        list(iter_frames_with_final(src))


def test_iter_frames_truncated_body():
    frame_body = b"hello"
    data = struct.pack(">I", len(frame_body)) + frame_body[:3]  # missing 2 bytes
    src = io.BytesIO(data)
    with pytest.raises(IntegrityError, match="truncated frame body"):
        list(iter_frames_with_final(src))
