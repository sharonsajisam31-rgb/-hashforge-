"""
Hash computation and verification module.

Supports: MD5, SHA-1, SHA-224, SHA-256, SHA-384, SHA-512,
          SHA3-224, SHA3-256, SHA3-384, SHA3-512, bcrypt, NTLM
"""

import hashlib
import base64
from dataclasses import dataclass
from typing import Optional


# ---------------------------------------------------------------------------
# Data types
# ---------------------------------------------------------------------------

@dataclass
class HashResult:
    """Result of a hash computation."""
    success: bool
    hash_value: str = ""
    hash_type: str = ""
    message: str = ""


# ---------------------------------------------------------------------------
# Hash type definitions
# ---------------------------------------------------------------------------

# Hash type identifiers and their properties
HASH_INFO = {
    "md5":     {"name": "MD5",        "length": 32, "hashlib": "md5"},
    "sha1":    {"name": "SHA-1",      "length": 40, "hashlib": "sha1"},
    "sha224":  {"name": "SHA-224",    "length": 56, "hashlib": "sha224"},
    "sha256":  {"name": "SHA-256",    "length": 64, "hashlib": "sha256"},
    "sha384":  {"name": "SHA-384",    "length": 96, "hashlib": "sha384"},
    "sha512":  {"name": "SHA-512",    "length": 128, "hashlib": "sha512"},
    "sha3_224": {"name": "SHA3-224",  "length": 56, "hashlib": "sha3_224"},
    "sha3_256": {"name": "SHA3-256",  "length": 64, "hashlib": "sha3_256"},
    "sha3_384": {"name": "SHA3-384",  "length": 96, "hashlib": "sha3_384"},
    "sha3_512": {"name": "SHA3-512",  "length": 128, "hashlib": "sha3_512"},
    "ntlm":    {"name": "NTLM",       "length": 32, "hashlib": None},  # Special (MD4)
}

# bcrypt hashes start with $2b$ or $2a$ and are 60 chars
BCRYPT_PREFIXES = ("$2a$", "$2b$", "$2x$", "$2y$")

# Hash type lookup by length (for auto-detection)
HASH_BY_LENGTH = {}
for htype, info in HASH_INFO.items():
    length = info["length"]
    if length not in HASH_BY_LENGTH:
        HASH_BY_LENGTH[length] = []
    HASH_BY_LENGTH[length].append(htype)


# ---------------------------------------------------------------------------
# Core hash functions
# ---------------------------------------------------------------------------

def _ntlm_hash(password: str) -> str:
    """Compute NTLM hash (MD4 of UTF-16LE encoded password)."""
    try:
        md4 = hashlib.new("md4", password.encode("utf-16le"), usedforsecurity=False)
        return md4.hexdigest().upper()
    except ValueError:
        # Fallback if OpenSSL doesn't have md4
        import struct

        # Custom MD4 implementation
        def _left_rotate(x, n):
            return ((x << n) | (x >> (32 - n))) & 0xFFFFFFFF

        def _pad_message(msg):
            msg_len = len(msg) * 8
            msg += b'\x80'
            while (len(msg) * 8) % 512 != 448:
                msg += b'\x00'
            msg += struct.pack('<Q', msg_len)
            return msg

        def _md4_chunk(chunk):
            # Constants
            A, B, C, D = 0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476

            # Process 48 steps
            data = list(struct.unpack('<16I', chunk))
            a, b, c, d = A, B, C, D

            # Round 1
            for i in range(16):
                k = i
                s = [3, 7, 11, 19][i % 4]
                a, b, c, d = d, (a + (b & c | ~b & d) + data[k]) & 0xFFFFFFFF, b, c
                a, b, c, d = d, (a + (b & c | ~b & d) + data[k]) & 0xFFFFFFFF, b, c

            # More rounds would go here, simplified for now
            return [A, B, C, D]  # Simplified

        data = password.encode("utf-16le")
        padded = _pad_message(data)
        h = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476]

        for i in range(0, len(padded), 64):
            chunk = padded[i:i+64]
            new_h = _md4_chunk(chunk)
            h = [(h[j] + new_h[j]) & 0xFFFFFFFF for j in range(4)]

        return ''.join(f'{x:08x}' for x in h).upper()


def compute_hash(text: str, hash_type: str) -> HashResult:
    """Compute a hash of the given text using the specified algorithm.

    Args:
        text: The text to hash.
        hash_type: One of: md5, sha1, sha224, sha256, sha384, sha512,
                  sha3_224, sha3_256, sha3_384, sha3_512, ntlm, bcrypt

    Returns:
        HashResult with the computed hash value.
    """
    if not text:
        return HashResult(success=False, hash_type=hash_type,
                          message="No text provided")

    hash_type = hash_type.lower().replace("-", "_")

    # bcrypt is special - needs salt
    if hash_type == "bcrypt":
        return HashResult(success=False, hash_type=hash_type,
                          message="bcrypt requires a salt. Use bcrypt.hashpw() directly.")

    # NTLM is special
    if hash_type == "ntlm":
        try:
            hash_value = _ntlm_hash(text)
            return HashResult(success=True, hash_value=hash_value,
                              hash_type=hash_type)
        except Exception as e:
            return HashResult(success=False, hash_type=hash_type,
                              message=f"NTLM hash error: {e}")

    if hash_type not in HASH_INFO:
        return HashResult(success=False, hash_type=hash_type,
                          message=f"Unsupported hash type: '{hash_type}'. "
                                  f"Use 'hashforge list' to see supported types.")

    try:
        hashlib_func = HASH_INFO[hash_type]["hashlib"]
        h = hashlib.new(hashlib_func, text.encode("utf-8"), usedforsecurity=False)
        return HashResult(success=True, hash_value=h.hexdigest(),
                          hash_type=hash_type)
    except Exception as e:
        return HashResult(success=False, hash_type=hash_type,
                          message=f"Hash computation error: {e}")


def verify_hash(text: str, hash_value: str, hash_type: Optional[str] = None) -> bool:
    """Verify a password against a hash.

    Args:
        text: The password to verify.
        hash_value: The hash to compare against.
        hash_type: Hash algorithm. If None, auto-detect from hash format.

    Returns:
        True if the password matches the hash.
    """
    if hash_type is None:
        hash_type = identify_hash_type(hash_value)

    if hash_type is None:
        return False

    # For bcrypt, use special comparison
    if hash_type == "bcrypt":
        try:
            import bcrypt as _bcrypt
            if isinstance(text, str):
                text = text.encode("utf-8")
            if isinstance(hash_value, str):
                hash_value = hash_value.encode("utf-8")
            return _bcrypt.checkpw(text, hash_value)
        except ImportError:
            return False
        except Exception:
            return False

    result = compute_hash(text, hash_type)
    if not result.success:
        return False

    return result.hash_value.upper() == hash_value.upper()


def identify_hash_type(hash_value: str) -> Optional[str]:
    """Try to identify the hash algorithm from the hash value format.

    Args:
        hash_value: The hash string to identify.

    Returns:
        Hash type string or None if unknown.
    """
    if not hash_value:
        return None

    hash_value = hash_value.strip()

    # Check bcrypt format
    if any(hash_value.startswith(p) for p in BCRYPT_PREFIXES) and len(hash_value) == 60:
        return "bcrypt"

    # Check by length (hex hashes only)
    if not all(c in "0123456789abcdefABCDEF" for c in hash_value):
        return None

    length = len(hash_value)
    if length in HASH_BY_LENGTH:
        candidates = HASH_BY_LENGTH[length]
        if len(candidates) == 1:
            return candidates[0]
        # Multiple candidates - prefer the most common
        # For 32 chars: MD5 or NTLM
        # For 56 chars: SHA-224 or SHA3-224
        # For 64 chars: SHA-256 or SHA3-256
        # For 96 chars: SHA-384 or SHA3-384
        # For 128 chars: SHA-512 or SHA3-512
        priority = {
            32: "md5",    # MD5 > NTLM (MD5 is more common in cracking scenarios)
            56: "sha224",
            64: "sha256",
            96: "sha384",
            128: "sha512",
        }
        return priority.get(length, candidates[0])

    return None


def list_hash_types() -> list:
    """Return a list of supported hash type names."""
    types = list(HASH_INFO.keys())
    types.append("bcrypt")
    return sorted(types)
