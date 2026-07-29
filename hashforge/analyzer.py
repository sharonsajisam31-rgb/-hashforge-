"""
Password strength analysis module.

Provides entropy calculation, character set detection,
crack-time estimation, and policy compliance checking.
"""

import math
import re
import time
from dataclasses import dataclass
from typing import Optional


# ---------------------------------------------------------------------------
# Data types
# ---------------------------------------------------------------------------

@dataclass
class PasswordReport:
    """Detailed analysis of a password's strength."""
    password: str
    length: int
    entropy_bits: float
    character_sets: list
    estimated_crack_time: str
    crack_time_seconds: float
    score: int  # 0-100
    strength_label: str  # Very Weak, Weak, Fair, Strong, Very Strong
    issues: list
    suggestions: list
    has_common_patterns: bool
    is_common_password: bool


# ---------------------------------------------------------------------------
# Common passwords list (top 100)
# ---------------------------------------------------------------------------

COMMON_PASSWORDS = {
    "123456", "password", "12345678", "qwerty", "123456789",
    "12345", "1234", "111111", "1234567", "sunshine",
    "qwerty123", "000000", "admin", "letmein", "welcome",
    "monkey", "dragon", "master", "football", "charlie",
    "trustno1", "passw0rd", "shadow", "michael", "superman",
    "123123", "ashley", "qwerty12345", "password1", "123qwe",
    "batman", "starwars", "iloveyou", "princess", "696969",
    "abc123", "password123", "123qweasd", "qwertyuiop", "pass123",
    "1q2w3e4r", "qwerty1", "123456a", "zaq1zaq1", "test123",
    "pass", "passwd", "qwerty123456", "qwerty123", "admin123",
    "letmein123", "welcome123", "football1", "baseball", "hockey",
    "summer2024", "winter2024", "spring2024", "autumn2024",
    "Password", "Password1", "Password123", "P@ssw0rd", "P@$$w0rd",
}

# Common patterns to detect
COMMON_PATTERNS = [
    (r"12345", "Sequential numbers"),
    (r"qwerty", "Keyboard pattern"),
    (r"asdfgh", "Keyboard pattern"),
    (r"zxcvbn", "Keyboard pattern"),
    (r"(.)\1{2,}", "Repeated characters (3+)"),
    (r"^(password|passw0rd)", "Based on 'password'"),
    (r"(202[0-9]|20[0-9]{2})", "Contains a year"),
    (r"^(admin|root)", "Based on 'admin' or 'root'"),
    (r"abc", "Sequential letters"),
    (r"(.)\1\1", "Triple repeated character"),
    (r"qwertyuiop", "Full keyboard row"),
    (r"asdfghjkl", "Full keyboard row"),
    (r"zxcvbnm", "Full keyboard row"),
    (r"test", "Contains 'test'"),
    (r"iloveyou", "Common phrase"),
    (r"letmein", "Common phrase"),
    (r"trustno1", "Common phrase"),
    (r"passw[0o]rd", "Leetspeak variant of 'password'"),
]


# ---------------------------------------------------------------------------
# Crack time estimation
# ---------------------------------------------------------------------------

# Approximate hash rates (hashes per second) for a single RTX 4090
# Based on hashcat benchmarks
HASH_RATES = {
    "md5":        1_000_000_000_000,   # 1 TH/s
    "sha1":         500_000_000_000,   # 500 GH/s
    "sha224":       200_000_000_000,   # 200 GH/s
    "sha256":       200_000_000_000,   # 200 GH/s
    "sha384":       100_000_000_000,   # 100 GH/s
    "sha512":        80_000_000_000,   # 80 GH/s
    "sha3_256":      50_000_000_000,   # 50 GH/s
    "sha3_512":      30_000_000_000,   # 30 GH/s
    "ntlm":      10_000_000_000_000,   # 10 TH/s
    "bcrypt":             1_000_000,   # 1 MH/s
    "unknown":          50_000_000,    # Conservative default
}

# Brute-force key space for character sets
CHARSET_SIZES = {
    "lowercase": 26,
    "uppercase": 26,
    "digits": 10,
    "special": 33,  # Common special chars !@#$%^&*()_+-=[]{}|;':\",./<>?`
    "space": 1,
}

CHARSET_NAMES = {
    "lowercase": "Lowercase letters (a-z)",
    "uppercase": "Uppercase letters (A-Z)",
    "digits": "Digits (0-9)",
    "special": "Special characters",
    "space": "Space",
}


# ---------------------------------------------------------------------------
# Analysis functions
# ---------------------------------------------------------------------------

def _detect_character_sets(password: str) -> list:
    """Detect which character sets are used in the password."""
    sets = []
    if re.search(r"[a-z]", password):
        sets.append("lowercase")
    if re.search(r"[A-Z]", password):
        sets.append("uppercase")
    if re.search(r"[0-9]", password):
        sets.append("digits")
    if re.search(r"[^a-zA-Z0-9\s]", password):
        sets.append("special")
    if " " in password:
        sets.append("space")
    return sets


def _calculate_entropy(password: str) -> float:
    """Calculate the Shannon entropy of a password.

    Higher entropy = more unpredictable.
    """
    if not password:
        return 0.0

    # Count character frequencies
    length = len(password)
    freq = {}
    for char in password:
        freq[char] = freq.get(char, 0) + 1

    # Calculate Shannon entropy
    entropy = 0.0
    for count in freq.values():
        p = count / length
        if p > 0:
            entropy -= p * math.log2(p)

    return round(entropy * length, 2)


def _estimate_bruteforce_entropy(password: str) -> float:
    """Estimate entropy based on character set size.

    This gives a more practical estimate than Shannon entropy.
    """
    sets = _detect_character_sets(password)
    charset_size = sum(CHARSET_SIZES.get(s, 0) for s in sets)
    if charset_size == 0:
        return 0.0

    return round(len(password) * math.log2(charset_size), 2)


def _estimate_crack_time(entropy: float, hash_type: str = "sha256") -> tuple:
    """Estimate time to crack a password with given entropy.

    Args:
        entropy: Password entropy in bits.
        hash_type: Hash algorithm for rate estimation.

    Returns:
        Tuple of (human_readable_time, seconds).
    """
    rate = HASH_RATES.get(hash_type, HASH_RATES["unknown"])
    combinations = 2 ** entropy
    seconds = combinations / rate

    time_units = [
        ("centuries", 365.25 * 24 * 3600 * 100),
        ("years", 365.25 * 24 * 3600),
        ("months", 30 * 24 * 3600),
        ("days", 24 * 3600),
        ("hours", 3600),
        ("minutes", 60),
        ("seconds", 1),
    ]

    for unit_name, unit_seconds in time_units:
        if seconds >= unit_seconds:
            value = seconds / unit_seconds
            if value >= 1000 and unit_name in ("months", "days", "hours", "minutes", "seconds"):
                continue  # Go up to larger unit
            if value >= 1:
                return (f"{value:.1f} {unit_name}", seconds)

    return ("instant", seconds)


def _check_patterns(password: str) -> list:
    """Check for common weak patterns in password."""
    issues = []
    lower_pw = password.lower()

    for pattern, description in COMMON_PATTERNS:
        if re.search(pattern, lower_pw):
            issues.append(description)
            break  # Only report first pattern match

    return issues


def _check_policy(password: str) -> list:
    """Check password against common policy rules."""
    suggestions = []

    if len(password) < 8:
        suggestions.append("Increase length to at least 8 characters")
    if len(password) < 12:
        suggestions.append("Consider using 12+ characters for better security")
    if not re.search(r"[a-z]", password):
        suggestions.append("Add lowercase letters")
    if not re.search(r"[A-Z]", password):
        suggestions.append("Add uppercase letters")
    if not re.search(r"[0-9]", password):
        suggestions.append("Add digits")
    if not re.search(r"[^a-zA-Z0-9]", password):
        suggestions.append("Add special characters (!@#$%^&* etc.)")
    if re.search(r"(.)\1{2,}", password):
        suggestions.append("Avoid repeated characters (aaa, 111, etc.)")
    if re.search(r"(123|abc|qwerty|asdf)", password.lower()):
        suggestions.append("Avoid sequential patterns (123, abc, qwerty)")

    return suggestions


def _score_password(password: str, entropy: float, issues: list, is_common: bool) -> int:
    """Calculate a 0-100 score for password strength."""
    score = 0

    # Length score (up to 40 points)
    if len(password) >= 16:
        score += 40
    elif len(password) >= 12:
        score += 30
    elif len(password) >= 10:
        score += 20
    elif len(password) >= 8:
        score += 10
    else:
        score += max(0, len(password) * 2)

    # Entropy score (up to 35 points)
    if entropy >= 100:
        score += 35
    elif entropy >= 80:
        score += 30
    elif entropy >= 60:
        score += 20
    elif entropy >= 40:
        score += 10
    else:
        score += 5

    # Character diversity (up to 15 points)
    sets = _detect_character_sets(password)
    score += min(len(sets) * 4, 15)

    # Penalties
    score -= len(issues) * 10
    if is_common:
        score -= 30
    if re.search(r"(.)\1{2,}", password):
        score -= 10

    return max(0, min(100, score))


def _strength_label(score: int) -> str:
    """Convert numeric score to human-readable label."""
    if score >= 80:
        return "Very Strong"
    elif score >= 60:
        return "Strong"
    elif score >= 40:
        return "Fair"
    elif score >= 20:
        return "Weak"
    else:
        return "Very Weak"


# ---------------------------------------------------------------------------
# Main analysis function
# ---------------------------------------------------------------------------

def analyze_password(password: str, hash_type: str = "sha256") -> PasswordReport:
    """Perform a comprehensive password strength analysis.

    Args:
        password: The password to analyze.
        hash_type: Hash algorithm for crack-time estimation (default: sha256).

    Returns:
        PasswordReport with detailed strength metrics.
    """
    if not password:
        return PasswordReport(
            password="", length=0, entropy_bits=0,
            character_sets=[], estimated_crack_time="N/A",
            crack_time_seconds=0, score=0, strength_label="Very Weak",
            issues=["No password provided"], suggestions=[],
            has_common_patterns=False, is_common_password=False,
        )

    # Calculate metrics
    sets_detected = _detect_character_sets(password)
    shannon_entropy = _calculate_entropy(password)
    bruteforce_entropy = _estimate_bruteforce_entropy(password)
    actual_entropy = max(shannon_entropy, bruteforce_entropy)

    # Check patterns
    pattern_issues = _check_patterns(password)
    is_common = password in COMMON_PASSWORDS

    # Score
    score = _score_password(password, actual_entropy, pattern_issues, is_common)

    # Crack time estimation (using bruteforce_entropy for the estimate)
    time_str, time_seconds = _estimate_crack_time(actual_entropy, hash_type)

    # Suggestions
    suggestions = _check_policy(password)

    # Build all issues
    all_issues = list(pattern_issues)
    if is_common:
        all_issues.insert(0, "Password is in the top 100 most common passwords!")
    if len(password) < 8:
        all_issues.append("Too short (less than 8 characters)")

    return PasswordReport(
        password=password,
        length=len(password),
        entropy_bits=actual_entropy,
        character_sets=sets_detected,
        estimated_crack_time=time_str,
        crack_time_seconds=time_seconds,
        score=score,
        strength_label=_strength_label(score),
        issues=all_issues,
        suggestions=suggestions,
        has_common_patterns=len(pattern_issues) > 0,
        is_common_password=is_common,
    )
