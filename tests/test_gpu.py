"""
Tests for GPU acceleration module.

All tests work both WITH and WITHOUT a CUDA GPU.
When no GPU is available, the CPU fallback is tested instead.
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from hashforge.gpu_accel import (
    get_gpu_info, GPUCracker, gpu_benchmark, get_cracker,
    _md5_hash_bytes, _sha256_hash_bytes,
)


def test_gpu_detection():
    """GPU detection should always return without errors."""
    info = get_gpu_info()
    # Should always return a GPUInfo object
    assert info is not None
    assert hasattr(info, "available")
    print(f"[PASS] GPU detection (available={info.available})")


def test_md5_hash_bytes():
    """Verify pure-Python MD5 produces correct results."""
    result = _md5_hash_bytes(b"hello")
    assert result == b"5d41402abc4b2a76b9719d911017c592", f"Got {result}"
    print("[PASS] MD5 hash bytes")


def test_md5_empty():
    """MD5 of empty string."""
    result = _md5_hash_bytes(b"")
    assert result == b"d41d8cd98f00b204e9800998ecf8427e"
    print("[PASS] MD5 empty string")


def test_md5_long_string():
    """MD5 of longer string (multi-block)."""
    result = _md5_hash_bytes(b"The quick brown fox jumps over the lazy dog")
    assert result == b"9e107d9d372bb6826bd81d3542a419d6"
    print("[PASS] MD5 long string")


def test_sha256_hash_bytes():
    """Verify pure-Python SHA-256 produces correct results."""
    result = _sha256_hash_bytes(b"hello")
    assert result == b"2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
    print("[PASS] SHA-256 hash bytes")


def test_sha256_empty():
    """SHA-256 of empty string."""
    result = _sha256_hash_bytes(b"")
    assert result == b"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    print("[PASS] SHA-256 empty string")


def test_gpu_cracker_creation():
    """GPUCracker should initialize without errors."""
    cracker = GPUCracker(batch_size=1000)
    assert cracker is not None
    # Should always give us a device name (GPU or CPU fallback)
    assert len(cracker.device_name) > 0
    print(f"[PASS] GPUCracker created (device={cracker.device_name})")


def test_gpu_cracker_crack_found():
    """GPUCracker should find a password that's in the word list."""
    words = ["hello", "world", "secret123", "test"]
    target_hash = "5d41402abc4b2a76b9719d911017c592"  # MD5 of "hello"

    cracker = GPUCracker(batch_size=1000)
    found, password, attempts = cracker.crack_batch(words, target_hash, "md5")

    assert found, f"Should find 'hello', got found={found}, password={password}"
    assert password == "hello"
    assert attempts >= 1
    print(f"[PASS] GPU crack found (password={password}, attempts={attempts})")


def test_gpu_cracker_crack_not_found():
    """GPUCracker should return not-found when password isn't in list."""
    words = ["hello", "world", "nope"]
    target_hash = "00000000000000000000000000000000"  # Not in list

    cracker = GPUCracker(batch_size=1000)
    found, password, attempts = cracker.crack_batch(words, target_hash, "md5")

    assert not found
    print(f"[PASS] GPU crack not found (attempts={attempts})")


def test_gpu_cracker_sha256():
    """GPUCracker should find SHA-256 hashes too."""
    from hashlib import sha256
    target_hash = sha256(b"secret123").hexdigest()

    words = ["hello", "world", "secret123", "test"]
    cracker = GPUCracker(batch_size=1000)
    found, password, attempts = cracker.crack_batch(words, target_hash, "sha256")

    assert found, f"Should find 'secret123' (SHA-256), got found={found}"
    assert password == "secret123"
    print(f"[PASS] GPU crack SHA-256 (found={password})")


def test_gpu_cracker_empty_list():
    """GPUCracker should handle empty word lists gracefully."""
    cracker = GPUCracker(batch_size=1000)
    found, password, attempts = cracker.crack_batch([], "anyhash", "md5")
    assert not found
    assert attempts == 0
    print("[PASS] GPU crack empty list")


def test_gpu_benchmark_runs():
    """Benchmark should complete without error (may use CPU fallback)."""
    result = gpu_benchmark(hash_type="md5", num_words=1000)
    assert result["hash_type"] == "md5"
    assert result["num_words"] == 1000
    assert result["time_seconds"] > 0
    assert result["hash_rate"] > 0
    print(f"[PASS] GPU benchmark (rate={result['rate_human']})")


def test_gpu_cracker_supports_hash():
    """Check hash type support."""
    cracker = GPUCracker()
    assert cracker.supports_hash("md5"), "MD5 should be GPU-accelerated"
    # SHA-256 uses CPU fallback (CUDA kernel not implemented)
    assert not cracker.supports_hash("sha256"), "SHA-256 uses CPU fallback"
    assert not cracker.supports_hash("sha1")
    assert not cracker.supports_hash("bcrypt")
    assert not cracker.supports_hash("ntlm")
    print("[PASS] GPU hash type support (MD5 only)")


def test_get_cracker_singleton():
    """get_cracker() should return a usable cracker."""
    cracker = get_cracker()
    assert cracker is not None
    assert len(cracker.device_name) > 0
    print(f"[PASS] get_cracker() singleton (device={cracker.device_name})")


def run_all():
    print()
    print("=" * 50)
    print("  HashForge - GPU Acceleration Test Suite")
    print("=" * 50)
    print()

    tests = [
        test_gpu_detection,
        test_md5_hash_bytes,
        test_md5_empty,
        test_md5_long_string,
        test_sha256_hash_bytes,
        test_sha256_empty,
        test_gpu_cracker_creation,
        test_gpu_cracker_crack_found,
        test_gpu_cracker_crack_not_found,
        test_gpu_cracker_sha256,
        test_gpu_cracker_empty_list,
        test_gpu_benchmark_runs,
        test_gpu_cracker_supports_hash,
        test_get_cracker_singleton,
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
