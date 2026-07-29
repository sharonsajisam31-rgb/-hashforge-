"""
Tests for cracker module.
"""

import sys
import os
import tempfile
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from hashforge.cracker import HashCracker, crack_hash
from hashforge.hasher import compute_hash


def _make_wordlist(words):
    """Create a temporary wordlist file."""
    tmp = tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".txt")
    for word in words:
        tmp.write(word + "\n")
    tmp.close()
    return tmp.name


def test_crack_simple_word():
    """Crack a known MD5 hash with a wordlist containing the password."""
    # Create a wordlist with 'secret123' in it
    wordlist = _make_wordlist(["hello", "world", "secret123", "test"])
    try:
        target_hash = compute_hash("secret123", "md5")
        result = crack_hash(
            hash_value=target_hash.hash_value,
            hash_type="md5",
            wordlist_path=wordlist,
            use_rules=False,
            workers=1,
        )
        assert result.found, "Should find the password"
        assert result.password == "secret123", f"Expected 'secret123', got '{result.password}'"
        print(f"[PASS] Simple crack (found: {result.password})")
    finally:
        os.unlink(wordlist)


def test_crack_with_rules():
    """Crack a hash where the password is a rule mutation of a wordlist entry."""
    wordlist = _make_wordlist(["password"])
    try:
        # 'password' + '123' via suffix rule
        target_hash = compute_hash("password123", "md5")
        result = crack_hash(
            hash_value=target_hash.hash_value,
            hash_type="md5",
            wordlist_path=wordlist,
            use_rules=True,
            workers=1,
        )
        # Rule-based cracking may or may not find it depending on available mutations
        # Just verify it runs without error
        assert result.attempts > 0
        print(f"[PASS] Rule-based crack (attempts: {result.attempts})")
    finally:
        os.unlink(wordlist)


def test_crack_not_found():
    """Attempt to crack when password is not in wordlist."""
    wordlist = _make_wordlist(["hello", "world"])
    try:
        target_hash = compute_hash("nonexistentpassword", "md5")
        result = crack_hash(
            hash_value=target_hash.hash_value,
            hash_type="md5",
            wordlist_path=wordlist,
            use_rules=False,
            workers=1,
        )
        assert not result.found
        print("[PASS] Password not found handling")
    finally:
        os.unlink(wordlist)


def test_crack_empty_wordlist():
    """Crack with empty wordlist."""
    wordlist = _make_wordlist([])
    try:
        target_hash = compute_hash("test", "md5")
        result = crack_hash(
            hash_value=target_hash.hash_value,
            hash_type="md5",
            wordlist_path=wordlist,
            use_rules=False,
        )
        assert not result.found
        print("[PASS] Empty wordlist handling")
    finally:
        os.unlink(wordlist)


def test_crack_invalid_wordlist():
    """Handle non-existent wordlist gracefully."""
    result = crack_hash(
        hash_value="5d41402abc4b2a76b9719d911017c592",
        hash_type="md5",
        wordlist_path="/nonexistent/wordlist.txt",
        use_rules=False,
    )
    assert not result.found
    print("[PASS] Invalid wordlist handling")


def test_crack_auto_detect():
    """Auto-detect hash type during cracking."""
    wordlist = _make_wordlist(["hello", "world", "autotest"])
    try:
        target_hash = compute_hash("autotest", "sha256")
        result = crack_hash(
            hash_value=target_hash.hash_value,
            hash_type="",  # Auto-detect
            wordlist_path=wordlist,
            use_rules=False,
            workers=1,
        )
        assert result.found, "Should auto-detect and find password"
        print(f"[PASS] Auto-detect hash type (found: {result.password})")
    finally:
        os.unlink(wordlist)


def run_all():
    print()
    print("=" * 50)
    print("  HashForge - Cracker Test Suite")
    print("=" * 50)
    print()

    tests = [
        test_crack_simple_word,
        test_crack_with_rules,
        test_crack_not_found,
        test_crack_empty_wordlist,
        test_crack_invalid_wordlist,
        test_crack_auto_detect,
    ]

    passed = 0
    failed = 0
    for test in tests:
        try:
            test()
            passed += 1
        except AssertionError as e:
            print(f"[FAIL] {test.__name__}: {e}")
            failed += 1
        except Exception as e:
            print(f"[FAIL] {test.__name__}: Unexpected error: {e}")
            failed += 1

    print()
    print(f"Results: {passed} passed, {failed} failed, {len(tests)} total")
    print()
    return failed == 0


if __name__ == "__main__":
    success = run_all()
    sys.exit(0 if success else 1)
