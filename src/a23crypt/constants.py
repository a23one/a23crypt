"""Format and operational constants."""

from a23crypt.numbers import KILOBYTE, MEGABYTE


# AEAD key size matches AES-256 / ChaCha20Poly1305 (256-bit keys).
KEY_SIZE_BYTES: int = 32

# Random salt mixed into HKDF per encryption. Eliminates nonce-reuse risk
# when the same `record_key` is used for multiple encryptions: each gets
# a fresh subkey because the salt differs.
SALT_SIZE_BYTES: int = 16

# Length of the per-frame noise seed (HKDF-derived from master keys).
# Never appears on the wire; secret-gated by HKDF preimage resistance.
NOISE_SEED_SIZE_BYTES: int = 16

# Streaming chunk size: each chunk is independently encrypted and framed.
MAX_CHUNK_SIZE_BYTES: int = 64 * KILOBYTE

# Single-shot ceiling. Above this, callers must use encrypt_stream.
MAX_SINGLE_SHOT_SIZE_BYTES: int = MEGABYTE

# Bytes-API decrypt ceiling. Set generously above the encrypt cap to allow
# for ciphertext expansion (AEAD tags, framing, noise, header). Larger
# inputs must use decrypt_stream so memory stays bounded per chunk.
MAX_SINGLE_SHOT_CIPHERTEXT_BYTES: int = 2 * MEGABYTE

# record_key max size (kilobytes-scale; well above realistic metadata).
CONTEXT_MAX_BYTES: int = 4 * KILOBYTE

# zstd compression level range (1 = fastest, 22 = best ratio).
ZSTD_MAX_LEVEL: int = 22
