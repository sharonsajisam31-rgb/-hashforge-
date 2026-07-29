"""
Tests for rules module.
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from hashforge.rules import generate_mutations, describe_rules, WordRuleEngine


def test_capitalization():
    mutations = generate_mutations("hello", rules=["caps"])
    assert "hello" in mutations
    assert "HELLO" in mutations
    assert "Hello" in mutations
    print("[PASS] Capitalization rules")


def test_leet_single():
    mutations = generate_mutations("hello", rules=["leet"])
    assert "hello" in mutations
    assert "h3llo" in mutations  # e -> 3
    print("[PASS] Leetspeak single substitution")


def test_leet_multi():
    mutations = generate_mutations("test", rules=["leet"])
    assert "t3st" in mutations  # e -> 3
    assert "te$t" in mutations  # s -> $
    print("[PASS] Leetspeak multi substitution")


def test_suffix():
    mutations = generate_mutations("password", rules=["suffix"])
    assert "password" in mutations
    assert "password123" in mutations
    assert "password2024" in mutations
    assert "password!" in mutations
    print("[PASS] Suffix rules")


def test_reverse():
    mutations = generate_mutations("hello", rules=["reverse"])
    rev = "olleh"
    assert rev in mutations
    print("[PASS] Reverse rules")


def test_double():
    mutations = generate_mutations("hello", rules=["double"])
    assert "hellohello" in mutations
    print("[PASS] Double rules")


def test_all_rules_size():
    mutations = generate_mutations("testword")
    assert len(mutations) > 10
    assert len(mutations) <= 50000  # max limit
    print(f"[PASS] All rules ({len(mutations)} mutations)")


def test_empty_word():
    mutations = generate_mutations("")
    assert len(mutations) == 0
    print("[PASS] Empty word")


def test_describe_rules():
    desc = describe_rules()
    assert "caps" in desc
    assert "leet" in desc
    assert "suffix" in desc
    print("[PASS] Describe rules")


def test_engine_max_mutations():
    engine = WordRuleEngine(max_mutations=100)
    mutations = engine.apply_all_rules("superlongwordtest")
    assert len(mutations) <= 100
    print("[PASS] Rule engine respects max limit")


def test_single_char():
    mutations = generate_mutations("a", rules=["caps"])
    assert "a" in mutations
    assert "A" in mutations
    print("[PASS] Single character")


def run_all():
    print()
    print("=" * 50)
    print("  HashForge - Rules Test Suite")
    print("=" * 50)
    print()

    tests = [
        test_capitalization,
        test_leet_single,
        test_leet_multi,
        test_suffix,
        test_reverse,
        test_double,
        test_all_rules_size,
        test_empty_word,
        test_describe_rules,
        test_engine_max_mutations,
        test_single_char,
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
