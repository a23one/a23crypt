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
"""

import hashlib


def add_noise(data: bytes, noise_seed: bytes) -> bytes:
    """Insert uniformly-distributed noise bytes between runs of real bytes.

    Per iteration, two bytes are consumed from a SHAKE-256 stream:
    the low nibble of the first gives the take count (0-15 real bytes
    appended), the second is the uniform noise byte.
    """
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


def remove_noise(noisy: bytes, noise_seed: bytes) -> bytes:
    """Inverse of `add_noise`. Same seed required."""
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
