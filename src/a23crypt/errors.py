"""Exception hierarchy.

All public exceptions inherit from `A23CryptError`, so callers can catch
the family with a single clause.
"""


class A23CryptError(Exception):
    """Base class for all a23crypt errors."""


class IntegrityError(A23CryptError):
    """Format-level failure: truncation, malformed header, oversized field."""


class DecryptionError(A23CryptError):
    """Cryptographic failure. Message intentionally uniform to avoid
    leaking which layer failed; details available via `__cause__`."""


class CompressionError(A23CryptError):
    """Compression or decompression failure."""


class InvalidKeyError(A23CryptError, ValueError):
    """A key was the wrong size or shape."""


class InputSizeError(A23CryptError, ValueError):
    """Input exceeded a configured size limit."""
