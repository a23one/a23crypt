"""Per-chunk zstd compression."""

import compression.zstd as zstd

from a23crypt.errors import CompressionError


def compress_chunk(chunk: bytes, *, level: int) -> bytes:
    """Compress a single chunk with zstd. One-shot; no state kept."""
    try:
        return zstd.compress(chunk, level=level)
    except zstd.ZstdError as e:  # pragma: no cover - defensive; unreachable from valid input
        raise CompressionError(f"chunk compression failed: {e}") from e


def decompress_chunk(chunk: bytes, *, max_output_size: int) -> bytes:
    """Decompress one zstd chunk, capped at max_output_size during decompression.

    Raises CompressionError on malformed input, output that would exceed
    the cap (bomb), incomplete frame, or trailing bytes after frame end.
    """
    if max_output_size <= 0:
        raise ValueError(
            f"max_output_size must be positive, got {max_output_size}"
        )

    decompressor = zstd.ZstdDecompressor()
    try:
        result = decompressor.decompress(chunk, max_length=max_output_size)
    except zstd.ZstdError as e:
        raise CompressionError(f"chunk decompression failed: {e}") from e

    if not decompressor.eof:
        if decompressor.needs_input:
            raise CompressionError(
                "incomplete zstd frame (corrupted compressed input)"
            )
        raise CompressionError(
            f"decompressed output would exceed max {max_output_size} "
            f"bytes (possible compression bomb)"
        )
    if decompressor.unused_data:
        raise CompressionError(
            f"trailing data after zstd frame "
            f"({len(decompressor.unused_data)} bytes)"
        )

    return result
