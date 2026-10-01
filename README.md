# a23crypt

Dual-key cascaded AEAD encryption with per-record key diversification.

- **Two independent keys** — `server_key` and `client_key` — give split-custody. Compromise of one alone yields no plaintext.
- **Per-record cryptographic isolation** — every record uses HKDF-derived subkeys, so compromise of one record's effective keys reveals nothing about other records.
- **Cascaded AEAD** — AES-256-GCM (inner) + ChaCha20Poly1305 (outer). Mixed hash families (SHA-512 / SHA3-512) for HKDF defend against a future weakening of either family.
- **Streaming with constant memory** — encrypt/decrypt files, sockets, or any binary stream of arbitrary size.
- **Optional zstd compression** — per-chunk, with built-in compression-bomb protection during decompression.
- **100% test coverage** — 266 parametrised tests covering round-trip, truncation, tampering, frame-level attacks, DoS, and cryptographic isolation.

---

## Install

```bash
uv add a23crypt
```

Requires **Python 3.14+** (uses stdlib `compression.zstd` from PEP 784).

## Quick example

```python
import os
import a23crypt

server_key = os.urandom(32)
client_key = os.urandom(32)
record_key = b"record-uuid-001"

ciphertext = a23crypt.encrypt(
    b"sensitive data",
    server_key=server_key,
    client_key=client_key,
    record_key=record_key,
    compress_level=3,
)

plaintext = a23crypt.decrypt(
    ciphertext,
    server_key=server_key,
    client_key=client_key,
    record_key=record_key,
)
```

## Streaming

For files, media, or any data above ~1 MB:

```python
with open("input.bin", "rb") as src, open("output.enc", "wb") as dst:
    a23crypt.encrypt_stream(
        src, dst,
        server_key=server_key,
        client_key=client_key,
        record_key=b"file-001",
        compress_level=3,
    )

with open("output.enc", "rb") as src, open("decrypted.bin", "wb") as dst:
    a23crypt.decrypt_stream(
        src, dst,
        server_key=server_key,
        client_key=client_key,
        record_key=b"file-001",
    )
```

For network sources that may return short reads, wrap in `io.BufferedReader`.

---

## Wire format

```
[magic:      1B]   format identifier
[flags:      1B]   bits 0-4 = zstd level (0 disables), bits 5-7 reserved
[chunk_size: 4B uint32 BE]
[rk_len:     4B uint32 BE]
[record_key: rk_len bytes]
[hkdf_salt:  16B]  per-encryption random; mixed into HKDF for subkey diversification
[frame_0]
[frame_1]
...
[frame_N]    where N is the final chunk
```

Each frame is `[length: 4B uint32 BE][body: N bytes]`. The body is the
outer-AEAD ciphertext + 16-byte Poly1305 tag.

The outer-AEAD plaintext per frame is `noise(inner_AEAD ciphertext)` — no seed prefix. The noise seed itself is **HKDF-derived from both master keys** (see Subkey derivation below) and never appears on the wire, so an attacker who breaks the outer AEAD still cannot compute the noise pattern without recovering at least one master key.

### Per-chunk pipeline

Encrypt (reverse on decrypt):

```
chunk
  → optional zstd
  → AES-256-GCM         with HKDF-SHA-512  server subkey   (innermost)
  → controlled noise    keyed by record_key + chunk_index
  → ChaCha20Poly1305    with HKDF-SHA3-512 client subkey   (outermost)
  → length-prefixed frame written to dst
```

The AAD on every chunk binds `(chunk_index, is_final, flags, chunk_size)`.
Truncation, reorder, header tamper, and flag-flip attacks all fail
AEAD verification.

### Subkey derivation

For each encryption:

```
server_sub = HKDF-SHA-512 (server_key, salt=record_key + hkdf_salt, info=server_label)
client_sub = HKDF-SHA3-512(client_key, salt=record_key + hkdf_salt, info=client_label)
```

`record_key` provides per-record diversification; the random `hkdf_salt`
provides per-encryption diversification. Together they ensure no two
encryptions share an effective subkey, even under the same `record_key`.
Mixed hash families are intentional. The two `info` labels differ to
domain-separate the inner and outer subkeys.

### Noise seed derivation (per chunk, secret-gated)

Each chunk's noise seed is HKDF-derived from **both master keys** plus
the per-record / per-encryption / per-chunk salt material:

```
noise_seed[chunk_i] = HKDF-SHA-256(
    IKM    = server_key || client_key,
    salt   = record_key || hkdf_salt || pack(">Q", chunk_i),
    info   = noise_label,
    length = 16
)
```

The seed never appears in any header or AEAD plaintext. An attacker who
breaks the outer ChaCha20Poly1305 layer (via implementation bug, side
channel, or future cryptanalysis) **still cannot compute the noise seed
without recovering at least one master key**. This makes the noise
layer a genuine third secret-gated step in the cascade, not just an
algorithm-gated obfuscation.

### Noise transform

A SHAKE-256 keystream derived from `noise_seed` drives both the
take-count nibbles (how many real bytes precede each noise byte) and
the noise byte values themselves. Noise byte values are uniformly
distributed over 0-255, so the noisy output is statistically
indistinguishable from the inner AEAD ciphertext under IND$-CPA. There
is no 0/1-byte tell or cycling-pattern tell that would let an attacker
identify noise positions in the noisy stream by inspection — a
necessary property if the layer is to hold under a hypothetical break
of the outer AEAD.

### Empty input

An empty plaintext is encoded as a single frame containing the zero-byte
plaintext with `is_final=True`. Header-only ciphertexts are detected at
decrypt and rejected as truncation.

---

## Security properties

### What is defended

| Threat | Defense |
|---|---|
| Truncation (header-only, mid-stream, frame drop) | `saw_final` enforcement + AAD `is_final` binding |
| Tampering at any byte position | Two-layer AEAD authentication |
| Frame reorder, duplication, cross-record substitution | AAD `chunk_index` + per-record HKDF subkeys |
| Header field tampering | `chunk_size` and `flags` bound into AAD; `record_key` matched on parse |
| Compression bombs | `ZstdDecompressor` with `max_length`; cap enforced *during* decompression |
| DoS via oversized length prefixes | Frame body capped at `2 × MAX_CHUNK_SIZE_BYTES` before allocation |

### What is *not* defended

- **Endpoint compromise.** If `server_key` or `client_key` leaks, that party's protection is gone.
- **Plaintext memory hygiene.** Decrypted bytes live in Python heap; we do not C-level wipe.
- **Side channels in caller code.** Library uses constant-time AEAD primitives; what callers do with the output is their responsibility.

### Encryption is non-deterministic by design

Each call to `encrypt` / `encrypt_stream` generates a fresh 16-byte random salt that is mixed into the HKDF subkey derivation and stored in the ciphertext header. As a result:

- Two encryptions of the same plaintext under the same keys and the same `record_key` produce **different** ciphertexts.
- Reusing `record_key` is safe — each encryption gets cryptographically independent subkeys via the per-encryption salt.
- AES-GCM and ChaCha20Poly1305 cannot suffer nonce reuse across encryptions; the (key, nonce) pair is fresh per record + per encryption.

This is the property that lets the library be used safely in mutable-record scenarios (e.g. updating a note's content) without any caller discipline around `record_key` rotation.

### Replay protection — not provided

The format does not include a nonce, timestamp, or counter that would let a decryptor detect "I have already processed this exact ciphertext." A replayed valid ciphertext decrypts successfully every time. If your application needs replay protection (encrypted messages, tokens, command authorization), include a nonce or timestamp inside the plaintext and have the application layer track processed values.

### Partial-write on decrypt failure

`decrypt_stream` writes plaintext as it processes chunks. On exception, `dst` may contain partial output from earlier chunks. For atomic semantics, use the bytes-API `decrypt` (which buffers internally and is atomic on success) or wrap streaming output in a `BytesIO` you only commit on success.

---

## Best practices

- **Keep `record_key` composite fields unpredictable and multi-dimensional**, especially if you use the library across multiple services. A weak / guessable `record_key` reduces per-record isolation to per-`record_key`-set isolation.
- **Generate keys with `os.urandom(32)`** or another CSPRNG. Never use predictable bytes as keys.
- **Rotate keys periodically** at the application layer. The library does not manage key lifetimes.
- **For passwords**, derive keys with Argon2id at the caller side; pass the 32-byte derived bytes as `server_key` / `client_key`. The library does not run a password KDF itself.

---

## API

### Bytes API (small data, ≤ `MAX_SINGLE_SHOT_SIZE_BYTES`)

```python
a23crypt.encrypt(
    data: bytes,
    *,
    server_key: bytes,
    client_key: bytes,
    record_key: bytes,
    compress_level: int = 0,
) -> bytes

a23crypt.decrypt(
    ciphertext: bytes,
    *,
    server_key: bytes,
    client_key: bytes,
    record_key: bytes,
) -> bytes
```

### Streaming API (any size, constant memory)

```python
a23crypt.encrypt_stream(
    src: BinaryIO,
    dst: BinaryIO,
    *,
    server_key: bytes,
    client_key: bytes,
    record_key: bytes,
    compress_level: int = 0,
) -> None

a23crypt.decrypt_stream(
    src: BinaryIO,
    dst: BinaryIO,
    *,
    server_key: bytes,
    client_key: bytes,
    record_key: bytes,
) -> None
```

### Exceptions

All exceptions inherit from `A23CryptError`:

| Exception | When |
|---|---|
| `IntegrityError` | Format-level failure (truncation, malformed header, oversized field, record_key mismatch, missing final chunk) |
| `DecryptionError` | Cryptographic failure (wrong key, tampered ciphertext) |
| `CompressionError` | Compression / decompression failure |
| `InvalidKeyError` | Key is wrong size or empty |
| `InputSizeError` | Input exceeds the bytes-API single-shot limit |

`InvalidKeyError` and `InputSizeError` also inherit from `ValueError` for compatibility with general validation handlers.

### Limits

| Constant | Value | Purpose |
|---|---|---|
| `KEY_SIZE_BYTES` | 32 | Required size of `server_key` / `client_key` |
| `MAX_CHUNK_SIZE_BYTES` | 65536 | Streaming chunk size |
| `MAX_SINGLE_SHOT_SIZE_BYTES` | 1048576 | Bytes-API encrypt ceiling — above this, use `encrypt_stream` |
| `MAX_SINGLE_SHOT_CIPHERTEXT_BYTES` | 2097152 | Bytes-API decrypt ceiling — above this, use `decrypt_stream` |
| `CONTEXT_MAX_BYTES` | 4096 | Maximum `record_key` size |
| `ZSTD_MAX_LEVEL` | 22 | Maximum `compress_level` |

---

## Threat model

a23crypt is designed for **at-rest encryption of records** where:

- Two parties (server and client) hold independent 32-byte keys.
- Records have unique, unpredictable `record_key` values acting as HKDF salts.
- Plaintext and ciphertext are processed by trusted code on both sides.

It is **not** a transport encryption protocol. For TLS-like in-flight encryption, use TLS. It is **not** a password-derived encryption scheme; if you want to derive keys from passwords, run Argon2id at the caller side and pass the 32-byte derived bytes as the keys. It does **not** provide replay protection — see "Replay protection" above.

---

## Testing

```bash
uv run pytest                                    # 266 tests, ~0.5s
uv run pytest --cov=a23crypt --cov-report=term   # 100% line coverage
```

Test suite is split by concern:

- `tests/test_integration.py` — round-trip across sizes and content patterns; stream/file API parity.
- `tests/test_compression.py` — every zstd level; efficacy assertions; bomb-cap enforcement.
- `tests/test_security.py` — truncation, bit-flip, header tamper, frame reorder/duplicate/substitute, frame-DoS.
- `tests/test_validation.py` — input validation boundaries.
- `tests/test_kdf.py` — HKDF determinism, independence, validation.
- `tests/test_noise.py` — noise round-trip, known-answer vectors, vectorized/scalar parity.
- `tests/test_streaming.py` — chunk and frame iterators, truncation and oversize limits.

---

## License

MIT — see [LICENSE](LICENSE).
