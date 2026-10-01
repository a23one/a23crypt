"""a23crypt — dual-key cascaded AEAD encryption with per-record key diversification."""

from a23crypt.core import (
    decrypt,
    decrypt_stream,
    encrypt,
    encrypt_stream,
)
from a23crypt.errors import (
    A23CryptError,
    CompressionError,
    DecryptionError,
    InputSizeError,
    IntegrityError,
    InvalidKeyError,
)

__version__ = "0.2.0"

__all__ = [
    "encrypt",
    "decrypt",
    "encrypt_stream",
    "decrypt_stream",
    "A23CryptError",
    "CompressionError",
    "DecryptionError",
    "InputSizeError",
    "IntegrityError",
    "InvalidKeyError",
]
