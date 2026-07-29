"""
Tests for hasher module.
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from hashforge.hasher import (
    compute_hash, verify_hash, identify_hash_type, list_hash_types
)


def test_md5():
    result = compute_hash("hello", "md5")
    assert result.success
    assert result.hash_value == "5d41402abc4b2a76b9719d911017c592"
    print("[PASS] MD5")


def test_sha256():
    result = compute_hash("hello", "sha256")
    assert result.success
    assert result.hash_value == "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
    print("[PASS] SHA-256")


def test_sha1():
    result = compute_hash("hello", "sha1")
    assert result.success
    assert result.hash_value == "aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d"
    print("[PASS] SHA-1")


def test_sha512():
    result = compute_hash("hello", "sha512")
    assert result.success
    assert len(result.hash_value) == 128
    print("[PASS] SHA-512")


def test_ntlm():
    result = compute_hash("hello", "ntlm")
    assert result.success
    assert len(result.hash_value) == 32
    print("[PASS] NTLM")


def test_verify_correct():
    assert verify_hash("hello", "5d41402abc4b2a76b9719d911017c592", "md5")
    print("[PASS] Verify correct")


def test_verify_wrong():
    assert not verify_hash("wrong", "5d41402abc4b2a76b9719d911017c592", "md5")
    print("[PASS] Verify wrong")


def test_auto_detect_md5():
    detected = identify_hash_type("5d41402abc4b2a76b9719d911017c592")
    assert detected == "md5"
    print("[PASS] Auto-detect MD5")


def test_auto_detect_sha256():
    detected = identify_hash_type("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
    assert detected == "sha256"
    print("[PASS] Auto-detect SHA-256")


def test_auto_detect_sha1():
    detected = identify_hash_type("da39a3ee5e6b4b0d3255bfef95601890afd80709")
    assert detected == "sha1"
    print("[PASS] Auto-detect SHA-1")


def test_auto_detect_unknown():
    detected = identify_hash_type("notahash")
    assert detected is None
    print("[PASS] Auto-detect unknown")


def test_empty_input():
    result = compute_hash("", "md5")
    assert not result.success
    print("[PASS] Empty input")


def test_unsupported_type():
    result = compute_hash("test", "fake_hash")
    assert not result.success
    print("[PASS] Unsupported type")


def test_bcrypt_compute():
    """Test bcrypt hash computation."""
    result = compute_hash("hello", "bcrypt")
    assert result.success, f"bcrypt should succeed: {result.message}"
    assert result.hash_value.startswith("$2b$") or result.hash_value.startswith("$2a$")
    assert len(result.hash_value) == 60
    print(f"[PASS] bcrypt compute ({result.hash_value[:30]}...)")


def test_bcrypt_verify():
    """Test bcrypt verification."""
    result = compute_hash("mypassword", "bcrypt")
    assert result.success
    assert verify_hash("mypassword", result.hash_value, "bcrypt")
    assert not verify_hash("wrongpassword", result.hash_value, "bcrypt")
    print("[PASS] bcrypt verify")


def test_bcrypt_auto_detect():
    """Test bcrypt hash auto-detection."""
    result = compute_hash("test", "bcrypt")
    assert result.success
    detected = identify_hash_type(result.hash_value)
    assert detected == "bcrypt", f"Expected bcrypt, got {detected}"
    print("[PASS] bcrypt auto-detect")


def test_bcrypt_different_salts():
    """Same password should produce different hashes each time (salt)."""
    h1 = compute_hash("hello", "bcrypt")
    h2 = compute_hash("hello", "bcrypt")
    assert h1.success and h2.success
    assert h1.hash_value != h2.hash_value, "bcrypt should use unique salts"
    print("[PASS] bcrypt different salts")


def test_list_types():
    types = list_hash_types()
    assert "md5" in types
    assert "sha256" in types
    assert "ntlm" in types
    assert "bcrypt" in types
    print("[PASS] List types")


def run_all():
    print()
    print("=" * 50)
    print("  HashForge - Hasher Test Suite")
    print("=" * 50)
    print()

    tests = [
        test_md5,
        test_sha256,
        test_sha1,
        test_sha512,
        test_ntlm,
        test_verify_correct,
        test_verify_wrong,
        test_auto_detect_md5,
        test_auto_detect_sha256,
        test_auto_detect_sha1,
        test_auto_detect_unknown,
        test_empty_input,
        test_unsupported_type,
        test_list_types,
        test_bcrypt_compute,
        test_bcrypt_verify,
        test_bcrypt_auto_detect,
        test_bcrypt_different_salts,
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
