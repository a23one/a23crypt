"""Per-chunk byte-stream expansion (noise layer).

Inserts pseudorandom noise bytes between runs of real bytes, keyed by a
seed. Sits between the inner and outer AEADs in the encrypt pipeline.
Reversible by `remove_noise` with the same seed.

A SHAKE-256 keystream derived from `noise_seed` drives both the
take-count nibbles (how many real bytes precede each noise byte) and
the noise byte values themselves. Noise byte values are uniformly
distributed over 0-255, so the noisy output is statistically
indistinguishable from the inner AEAD ciphertext under IND$-CPA — no
0/1-byte tell or cycling-pattern tell that would let an attacker
identify noise positions by inspection.

Two byte-identical implementations: a scalar loop (the reference) and
a numpy vectorization that computes every noise position up front from
a cumulative sum of the take counts. Inputs below
`_VECTORIZE_MIN_BYTES` use the scalar loop, where numpy's per-call
overhead outweighs its throughput.
"""

import hashlib

import numpy as np


# Below this size the scalar loop is faster than numpy (measured
# crossover ≈ 320 bytes). Must stay ≥ 1: the vectorized path assumes
# non-empty input.
_VECTORIZE_MIN_BYTES: int = 320

# The vectorized path first requests `length // _FIRST_PASS_DIVISOR + 64`
# iterations of keystream. Expected use is ≈ length / 7.5, so this runs
# short with probability < 2^-80; see `_keystream`.
_FIRST_PASS_DIVISOR: int = 6


def add_noise(data: bytes, noise_seed: bytes) -> bytes:
    """Insert uniformly-distributed noise bytes between runs of real bytes.

    Per iteration, two bytes are consumed from a SHAKE-256 stream:
    the low nibble of the first gives the take count (0-15 real bytes
    appended), the second is the uniform noise byte.
    """
    if len(data) < _VECTORIZE_MIN_BYTES:
        return _add_noise_scalar(data, noise_seed)
    return _add_noise_vectorized(data, noise_seed)


def remove_noise(noisy: bytes, noise_seed: bytes) -> bytes:
    """Inverse of `add_noise`. Same seed required."""
    if len(noisy) < _VECTORIZE_MIN_BYTES:
        return _remove_noise_scalar(noisy, noise_seed)
    return _remove_noise_vectorized(noisy, noise_seed)


def _add_noise_scalar(data: bytes, noise_seed: bytes) -> bytes:
    # Two stream bytes per iteration. Iterations expected ≈ len(data) / 7.5
    # under a uniform stream; buffer of len(data) + 64 iterations is well
    # beyond any realistic upper bound.
    iter_budget = len(data) + 64
    stream = hashlib.shake_256(noise_seed).digest(2 * iter_budget)

    output = bytearray()
    pos = 0
    idx = 0
    while pos < len(data):
        offset = idx * 2
        take = min(stream[offset] & 0xF, len(data) - pos)
        output.extend(data[pos : pos + take])
        pos += take
        output.append(stream[offset + 1])
        idx += 1
    return bytes(output)


def _remove_noise_scalar(noisy: bytes, noise_seed: bytes) -> bytes:
    iter_budget = len(noisy) + 64
    stream = hashlib.shake_256(noise_seed).digest(2 * iter_budget)

    output = bytearray()
    pos = 0
    idx = 0
    while pos < len(noisy):
        offset = idx * 2
        take_count = stream[offset] & 0xF
        # Reserve one byte for the mandatory trailing noise byte.
        available = max(len(noisy) - pos - 1, 0)
        take = min(take_count, available)
        output.extend(noisy[pos : pos + take])
        pos += take
        if pos < len(noisy):
            pos += 1  # skip noise byte
        idx += 1
    return bytes(output)


def _keystream(
    noise_seed: bytes, length: int, stride: int
) -> tuple[np.ndarray, np.ndarray]:
    """Return (run ends, noise bytes) from the SHAKE-256 stream.

    `ends[i]` is the input offset reached after iteration i, where each
    iteration advances by its take count plus `stride` (0 when the input
    holds only real bytes, 1 when every run is followed by a noise
    byte). The stream is long enough that `ends[-1] >= length`.
    """
    # SHAKE-256 is an XOF: a longer digest extends a shorter one. So a
    # short first pass shares its prefix with the scalar path's full
    # `length + 64` budget, and falling back to that budget is exact.
    for iterations in (length // _FIRST_PASS_DIVISOR + 64, length + 64):
        digest = hashlib.shake_256(noise_seed).digest(2 * iterations)
        stream = np.frombuffer(digest, dtype=np.uint8)
        ends = np.cumsum((stream[0::2] & 0xF) + stride, dtype=np.int64)
        if ends[-1] >= length:
            break
    return ends, stream[1::2]


def _add_noise_vectorized(data: bytes, noise_seed: bytes) -> bytes:
    n = len(data)
    ends, noise = _keystream(noise_seed, n, stride=0)
    # The scalar loop runs until a run reaches the end of `data`.
    iterations = int(np.searchsorted(ends, n)) + 1
    # Noise byte i follows the real bytes taken so far (the final run is
    # clamped to the end of `data`) and the i noise bytes before it.
    noise_at = np.minimum(ends[:iterations], n) + np.arange(iterations)

    output = np.empty(n + iterations, dtype=np.uint8)
    is_real = np.ones(n + iterations, dtype=bool)
    is_real[noise_at] = False
    output[noise_at] = noise[:iterations]
    output[is_real] = np.frombuffer(data, dtype=np.uint8)
    return output.tobytes()


def _remove_noise_vectorized(noisy: bytes, noise_seed: bytes) -> bytes:
    n = len(noisy)
    ends, _ = _keystream(noise_seed, n, stride=1)
    iterations = int(np.searchsorted(ends, n)) + 1
    # Each run ends with its noise byte; the scalar loop clamps the final
    # run so its noise byte is the last byte of `noisy`.
    noise_at = np.minimum(ends[:iterations], n) - 1

    is_real = np.ones(n, dtype=bool)
    is_real[noise_at] = False
    return np.frombuffer(noisy, dtype=np.uint8)[is_real].tobytes()
