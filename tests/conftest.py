"""Shared test constants.

Constants only — no pytest fixtures. Imported as module-level names by
individual test modules so that test code reads naturally without
fixture-injection ceremony for values that are universally constant
across the suite.
"""

# Standard test keys. Real keys must come from a CSPRNG; these are only
# safe in tests where confidentiality of the test data does not matter.
SERVER_KEY: bytes = b"s" * 32
CLIENT_KEY: bytes = b"c" * 32
ALT_SERVER_KEY: bytes = b"S" * 32
ALT_CLIENT_KEY: bytes = b"C" * 32
RECORD_KEY: bytes = b"rec_001"
ALT_RECORD_KEY: bytes = b"rec_002"
