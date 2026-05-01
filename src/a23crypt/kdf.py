"""HKDF-based subkey derivation."""

from cryptography.hazmat.primitives.hashes import HashAlgorithm
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from a23crypt.constants import KEY_SIZE_BYTES


def derive_subkey(
    key_material: bytes,
    *,
    salt: bytes,
    info: bytes,
    hash_alg: HashAlgorithm,
    length: int = KEY_SIZE_BYTES,
) -> bytes:
    """Derive a subkey from key material via HKDF.

    Args:
        key_material: Master secret. At least 16 bytes; 32 recommended.
        salt: Per-context diversifier. Different salts → independent
            outputs. Not secret.
        info: Per-purpose label. Different infos → independent outputs.
        hash_alg: HMAC hash (SHA512, SHA3_512, etc.).
        length: Output size in bytes (default: 32).

    Raises:
        ValueError: key_material < 16 bytes or empty info.
    """
    if len(key_material) < 16:
        raise ValueError(
            f"key_material must be at least 16 bytes, got {len(key_material)}"
        )
    if not info:
        raise ValueError("info must be non-empty for domain separation")

    return HKDF(
        algorithm=hash_alg,
        length=length,
        salt=salt,
        info=info,
    ).derive(key_material)
