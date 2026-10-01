"""Benchmark the noise layer: scalar (original pure-Python) vs current.

    uv run python benchmarks/bench_noise.py

The baseline swaps the scalar implementations into `a23crypt.core`, so
end-to-end numbers compare the full pipeline with only the noise layer
changed.
"""

import io
import os
import timeit
from collections.abc import Callable
from functools import partial

import a23crypt
import a23crypt.core
from a23crypt import noise
from a23crypt.constants import MAX_SINGLE_SHOT_SIZE_BYTES
from a23crypt.numbers import KILOBYTE, MEGABYTE


KEYS = dict(
    server_key=os.urandom(32),
    client_key=os.urandom(32),
    record_key=b"bench",
)

IMPLEMENTATIONS = {
    "scalar": (noise._add_noise_scalar, noise._remove_noise_scalar),
    "current": (noise.add_noise, noise.remove_noise),
}


def best_seconds(fn: Callable[[], object], budget_seconds: float = 0.2) -> float:
    """Best per-call time over 7 repeats, each sized to ~budget_seconds."""
    number, elapsed = timeit.Timer(fn).autorange()
    number = max(1, int(number * budget_seconds / elapsed))
    return min(timeit.repeat(fn, number=number, repeat=7)) / number


def fmt_time(seconds: float) -> str:
    if seconds < 1e-3:
        return f"{seconds * 1e6:8.1f} µs"
    return f"{seconds * 1e3:8.2f} ms"


def fmt_size(n: int) -> str:
    if n >= MEGABYTE:
        return f"{n // MEGABYTE} MiB"
    if n >= KILOBYTE:
        return f"{n // KILOBYTE} KiB"
    return f"{n} B"


def encrypt_stream(data: bytes) -> bytes:
    dst = io.BytesIO()
    a23crypt.encrypt_stream(io.BytesIO(data), dst, **KEYS)
    return dst.getvalue()


def decrypt_stream(ciphertext: bytes) -> bytes:
    dst = io.BytesIO()
    a23crypt.decrypt_stream(io.BytesIO(ciphertext), dst, **KEYS)
    return dst.getvalue()


def bench_noise_layer() -> None:
    print("noise layer (add_noise / remove_noise)")
    print(f"{'size':>8}  {'scalar add':>11}  {'current add':>11}  {'speedup':>7}"
          f"  {'scalar rm':>11}  {'current rm':>11}  {'speedup':>7}")
    seed = os.urandom(16)
    for size in (32, 256, KILOBYTE, 4 * KILOBYTE, 16 * KILOBYTE, 64 * KILOBYTE):
        data = os.urandom(size)
        noisy = noise.add_noise(data, seed)
        add, rm = {}, {}
        for name, (add_fn, remove_fn) in IMPLEMENTATIONS.items():
            add[name] = best_seconds(partial(add_fn, data, seed))
            rm[name] = best_seconds(partial(remove_fn, noisy, seed))
        print(f"{fmt_size(size):>8}  {fmt_time(add['scalar'])}  {fmt_time(add['current'])}"
              f"  {add['scalar'] / add['current']:6.1f}x"
              f"  {fmt_time(rm['scalar'])}  {fmt_time(rm['current'])}"
              f"  {rm['scalar'] / rm['current']:6.1f}x")


def bench_end_to_end() -> None:
    print("\nend-to-end (encrypt / decrypt, bytes API ≤ 1 MiB, stream API above)")
    print(f"{'size':>8}  {'impl':>8}  {'encrypt':>11}  {'MiB/s':>8}  {'decrypt':>11}  {'MiB/s':>8}")
    for size in (32, 256, KILOBYTE, 64 * KILOBYTE, MEGABYTE, 16 * MEGABYTE):
        if size <= MAX_SINGLE_SHOT_SIZE_BYTES:
            encrypt = partial(a23crypt.encrypt, **KEYS)
            decrypt = partial(a23crypt.decrypt, **KEYS)
        else:
            encrypt, decrypt = encrypt_stream, decrypt_stream
        data = os.urandom(size)
        ciphertext = encrypt(data)

        results = {}
        for name, (add, remove) in IMPLEMENTATIONS.items():
            a23crypt.core.add_noise, a23crypt.core.remove_noise = add, remove
            results[name] = (
                best_seconds(partial(encrypt, data)),
                best_seconds(partial(decrypt, ciphertext)),
            )
        a23crypt.core.add_noise, a23crypt.core.remove_noise = IMPLEMENTATIONS["current"]

        for name, (enc, dec) in results.items():
            print(f"{fmt_size(size):>8}  {name:>8}  {fmt_time(enc)}  {size / MEGABYTE / enc:8.1f}"
                  f"  {fmt_time(dec)}  {size / MEGABYTE / dec:8.1f}")
        (base_enc, base_dec), (enc, dec) = results["scalar"], results["current"]
        print(f"{'':>8}  {'speedup':>8}  {base_enc / enc:10.1f}x  {'':>8}  {base_dec / dec:10.1f}x")


if __name__ == "__main__":
    bench_noise_layer()
    bench_end_to_end()
