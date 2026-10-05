"""Compare a23crypt with the usual single-key alternatives.

    uv run python benchmarks/bench_compare.py

Baselines, all from pyca/cryptography:
  - Fernet: the default "just encrypt it" recipe in Python
    (AES-128-CBC + HMAC-SHA256, base64 output).
  - AES-256-GCM alone: one raw AEAD layer, the speed floor.

Reports per-call time for a small record and a large one, and the
ciphertext size each scheme produces.
"""

import json
import os
import timeit
from collections.abc import Callable

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

import a23crypt
from a23crypt.numbers import KILOBYTE, MEGABYTE


SERVER_KEY = os.urandom(32)
CLIENT_KEY = os.urandom(32)
RECORD_KEY = b"user-7f3a9c41"
KEYS = dict(server_key=SERVER_KEY, client_key=CLIENT_KEY, record_key=RECORD_KEY)

FERNET = Fernet(Fernet.generate_key())
AES = AESGCM(AESGCM.generate_key(bit_length=256))
NONCE = os.urandom(12)


def best_seconds(fn: Callable[[], object], budget_seconds: float = 0.3) -> float:
    """Best per-call time over 7 repeats, each sized to ~budget_seconds."""
    number, elapsed = timeit.Timer(fn).autorange()
    number = max(1, int(number * budget_seconds / elapsed))
    return min(timeit.repeat(fn, number=number, repeat=7)) / number


def sample_record() -> bytes:
    """A realistic JSON row: a user profile with some free text."""
    return json.dumps({
        "id": "user-7f3a9c41",
        "email": "ada@example.com",
        "name": "Ada Lovelace",
        "plan": "team",
        "created_at": "2026-05-01T09:30:00Z",
        "address": {"line1": "12 St James's Square", "city": "London", "postcode": "SW1Y 4JH"},
        "notes": "Prefers email. " * 40,
        "tags": ["beta", "billing-admin", "eu"],
    }).encode()


def schemes(data: bytes) -> dict[str, tuple[Callable[[], bytes], Callable[[], bytes]]]:
    sealed = a23crypt.encrypt(data, **KEYS)
    fernet_token = FERNET.encrypt(data)
    aes_ct = AES.encrypt(NONCE, data, None)
    return {
        "a23crypt": (lambda: a23crypt.encrypt(data, **KEYS), lambda: a23crypt.decrypt(sealed, **KEYS)),
        "Fernet": (lambda: FERNET.encrypt(data), lambda: FERNET.decrypt(fernet_token)),
        "AES-256-GCM alone": (lambda: AES.encrypt(NONCE, data, None), lambda: AES.decrypt(NONCE, aes_ct, None)),
    }


def fmt(seconds: float, size: int) -> str:
    rate = size / seconds / MEGABYTE
    if seconds < 1e-3:
        return f"{seconds * 1e6:8.1f} µs  {rate:7.0f} MiB/s"
    return f"{seconds * 1e3:8.2f} ms  {rate:7.0f} MiB/s"


def bench_speed() -> None:
    for label, data in (("1 KiB record", os.urandom(KILOBYTE)), ("1 MiB blob", os.urandom(MEGABYTE))):
        print(f"\n{label}")
        print(f"{'':20}  {'encrypt':>22}  {'decrypt':>22}")
        for name, (enc, dec) in schemes(data).items():
            print(f"{name:20}  {fmt(best_seconds(enc), len(data))}  {fmt(best_seconds(dec), len(data))}")


def bench_size() -> None:
    record = sample_record()
    rows = {
        "a23crypt": len(a23crypt.encrypt(record, **KEYS)),
        "a23crypt, compress_level=3": len(a23crypt.encrypt(record, compress_level=3, **KEYS)),
        "Fernet": len(FERNET.encrypt(record)),
        "AES-256-GCM alone (+ nonce)": len(AES.encrypt(NONCE, record, None)) + len(NONCE),
    }
    print(f"\nciphertext size for a {len(record)}-byte JSON record")
    for name, n in rows.items():
        print(f"{name:28}  {n:6} bytes  {n / len(record):5.2f}x")


if __name__ == "__main__":
    bench_speed()
    bench_size()
