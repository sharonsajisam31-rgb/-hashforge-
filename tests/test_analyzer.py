"""
Tests for analyzer module.
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from hashforge.analyzer import analyze_password


def test_weak_password():
    report = analyze_password("password")
    assert report.score < 30
    assert report.is_common_password
    assert len(report.issues) > 0
    print("[PASS] Weak password detection")


def test_strong_password():
    report = analyze_password("kD8#mP2$vL9@nQ5%")
    assert report.score >= 60
    assert not report.is_common_password
    print("[PASS] Strong password detection")


def test_entropy_calculation():
    report = analyze_password("abc")
    assert report.entropy_bits > 0
    print("[PASS] Entropy calculation")


def test_length_detection():
    report = analyze_password("short")
    assert report.length == 5
    assert "8 characters" in report.suggestions[0]
    print("[PASS] Length detection")


def test_character_sets():
    report = analyze_password("Abc123!@")
    sets = report.character_sets
    assert "uppercase" in sets
    assert "lowercase" in sets
    assert "digits" in sets
    assert "special" in sets
    print("[PASS] Character set detection")


def test_missing_sets():
    report = analyze_password("abc123")
    sets = report.character_sets
    assert "uppercase" not in sets
    assert "special" not in sets
    print("[PASS] Missing set detection")


def test_crack_time_estimate():
    report = analyze_password("verylongandsecurepassword2024!")
    assert report.crack_time_seconds > 0
    assert report.estimated_crack_time != "N/A"
    print("[PASS] Crack time estimation")


def test_common_patterns():
    report = analyze_password("password123")
    assert len(report.issues) > 0
    print("[PASS] Common pattern detection")


def test_empty_password():
    report = analyze_password("")
    assert report.score == 0
    assert report.strength_label == "Very Weak"
    print("[PASS] Empty password")


def test_long_password():
    report = analyze_password("a" * 50)
    assert report.length == 50
    assert report.score < 60  # Low entropy due to repetition
    print("[PASS] Long but weak password")


def run_all():
    print()
    print("=" * 50)
    print("  HashForge - Analyzer Test Suite")
    print("=" * 50)
    print()

    tests = [
        test_weak_password,
        test_strong_password,
        test_entropy_calculation,
        test_length_detection,
        test_character_sets,
        test_missing_sets,
        test_crack_time_estimate,
        test_common_patterns,
        test_empty_password,
        test_long_password,
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
