"""
Word mutation rule engine for hash cracking.

Provides a comprehensive set of word mutation rules:
- Capitalization (uppercase, lowercase, capitalize, toggle)
- Leetspeak substitutions (a->@4, e->3, s->$5, etc.)
- Suffix appending (years, numbers, special chars)
- Prefix prepending (common patterns)
- Reversal
- Truncation
- Combinations (multiple rules applied together)
"""

import itertools
from typing import List, Set, Optional


# ---------------------------------------------------------------------------
# Leetspeak mapping tables
# ---------------------------------------------------------------------------

LEET_TABLE = {
    'a': ['a', '@', '4', 'A'],
    'b': ['b', '8', 'B'],
    'c': ['c', '(', '<', 'C'],
    'e': ['e', '3', 'E'],
    'g': ['g', '9', '6', 'G'],
    'h': ['h', '#', 'H'],
    'i': ['i', '1', '!', 'I'],
    'l': ['l', '1', '|', 'L'],
    'o': ['o', '0', 'O'],
    's': ['s', '$', '5', 'S'],
    't': ['t', '7', '+', 'T'],
    'z': ['z', '2', 'Z'],
}

# Letters that can be leet-substituted
LEETABLE_LETTERS = set(LEET_TABLE.keys())

# Common suffix patterns
COMMON_SUFFIXES = [
    # Years
    "1", "12", "123", "1234",
    "0", "00", "000",
    "69", "666",
    "2020", "2021", "2022", "2023", "2024", "2025", "2026",
    "20", "21", "22", "23", "24", "25", "26",
    "99", "007",
    # Special chars
    "!", "!!", "!!!",
    "@",
    "#",
    "$",
    "?",
    ".",
    "!@#",
    # Numbers
    "1", "2", "3", "12", "123", "1234",
    "01", "02",
    "7", "77", "777",
]

# Common prefix patterns
COMMON_PREFIXES = [
    "!", "@", "#", "$",
    "Mr_", "Mrs_", "Dr_",
    "the", "The", "THE",
    "my", "My", "MY",
    "super", "Super",
]

# Common capitalization patterns
CAPITALIZATION_PATTERNS = [
    "lowercase",      # hello
    "uppercase",      # HELLO
    "capitalize",     # Hello
    "toggle_case",    # hELLO (first letter lowercase, rest inverted)
    "alternating",    # HeLlO
    "invert_case",    # hELLO (swap all cases)
    "camel",          # hello_world -> helloWorld (after removing separator)
]


# ---------------------------------------------------------------------------
# Rule Engine
# ---------------------------------------------------------------------------

class WordRuleEngine:
    """Rule engine for generating password mutations from base words."""

    def __init__(self, max_mutations: int = 100000):
        """Initialize the rule engine.

        Args:
            max_mutations: Maximum number of mutations to generate per word.
                          Prevents runaway memory usage.
        """
        self.max_mutations = max_mutations

    # ------------------------------------------------------------------
    # Individual Rule Methods
    # ------------------------------------------------------------------

    def apply_capitalization(self, word: str) -> List[str]:
        """Apply all capitalization variants."""
        if not word:
            return []

        results = set()
        results.add(word.lower())
        results.add(word.upper())

        # Capitalize (first letter upper, rest lower)
        results.add(word.capitalize())

        # Toggle case (swap case of each letter)
        results.add(word.swapcase())

        # First letter lower, rest same
        if len(word) > 1:
            results.add(word[0].lower() + word[1:])

        # All but first letter uppercase
        if len(word) > 1:
            results.add(word[0].upper() + word[1:].lower())

        # Alternating case (HeLlO)
        alt = ""
        for i, c in enumerate(word):
            alt += c.upper() if i % 2 == 0 else c.lower()
        results.add(alt)

        return list(results)

    def apply_leet(self, word: str, max_variants: int = 500) -> List[str]:
        """Apply leetspeak substitutions.

        For each leetable letter in the word, generates variants
        with that letter replaced by its leet equivalent.
        Limited to max_variants to prevent combinatorial explosion.
        """
        if not word:
            return []

        word_lower = word.lower()
        leetable_positions = []

        for i, char in enumerate(word_lower):
            if char in LEET_TABLE:
                leetable_positions.append(i)

        if not leetable_positions:
            return [word] if word else []

        results = set()
        results.add(word)

        # Single substitution (most useful)
        for pos in leetable_positions:
            char = word_lower[pos]
            for replacement in LEET_TABLE[char]:
                if replacement != char:
                    mutated = word[:pos] + replacement + word[pos+1:]
                    results.add(mutated)

        # Double substitutions (only for common combos to limit size)
        if len(leetable_positions) >= 2 and len(results) < max_variants:
            for i in range(len(leetable_positions)):
                for j in range(i + 1, len(leetable_positions)):
                    for r1 in LEET_TABLE[word_lower[leetable_positions[i]]]:
                        for r2 in LEET_TABLE[word_lower[leetable_positions[j]]]:
                            word_list = list(word)
                            word_list[leetable_positions[i]] = r1
                            word_list[leetable_positions[j]] = r2
                            results.add("".join(word_list))
                            if len(results) >= max_variants:
                                break
                        if len(results) >= max_variants:
                            break
                    if len(results) >= max_variants:
                        break
                if len(results) >= max_variants:
                    break

        return list(results)

    def apply_suffix(self, word: str, suffixes: Optional[List[str]] = None) -> List[str]:
        """Append common suffixes to the word."""
        if not word:
            return []

        results = set()
        results.add(word)

        suffixes = suffixes or COMMON_SUFFIXES
        for suffix in suffixes:
            results.add(word + suffix)
            # Capitalized word + suffix
            results.add(word.capitalize() + suffix)
            # uppercase word + suffix
            results.add(word.upper() + suffix)

        return list(results)

    def apply_prefix(self, word: str, prefixes: Optional[List[str]] = None) -> List[str]:
        """Prepend common prefixes to the word."""
        if not word:
            return []

        results = set()
        results.add(word)

        prefixes = prefixes or COMMON_PREFIXES
        for prefix in prefixes:
            results.add(prefix + word)
            results.add(prefix + word.capitalize())

        return list(results)

    def apply_reverse(self, word: str) -> List[str]:
        """Reverse the word."""
        if not word:
            return []
        return [word[::-1], word[::-1].capitalize(), word[::-1].upper()]

    def apply_truncate(self, word: str, min_length: int = 3) -> List[str]:
        """Generate truncated variants (remove last 1-3 chars)."""
        if not word or len(word) <= min_length:
            return [word] if word else []

        results = set()
        for n in range(1, min(4, len(word) - min_length + 1)):
            truncated = word[:-n]
            results.add(truncated)
            results.add(truncated.capitalize())
            results.add(truncated.upper())

        return list(results)

    def apply_double(self, word: str) -> List[str]:
        """Double the word (wordword)."""
        if not word:
            return []
        return [word + word, word.upper() + word, word + word.upper()]

    # ------------------------------------------------------------------
    # Combined Rule Application
    # ------------------------------------------------------------------

    def apply_all_rules(self, word: str) -> Set[str]:
        """Apply ALL rules to generate mutations.

        Applies rules in stages:
        1. Basic: capitalization, reverse, double
        2. Suffixes: year, number, special chars
        3. Leetspeak: single and double substitutions
        4. Prefixes
        5. Combined: capitalize + leet, capitalize + suffix, leet + suffix

        Returns a set of unique mutations.
        """
        if not word:
            return set()

        mutations = set()
        mutations.add(word)

        # Stage 1: Capitalization and basic transforms
        caps = self.apply_capitalization(word)
        mutations.update(caps)

        reverse_variants = self.apply_reverse(word)
        mutations.update(reverse_variants)

        double_variants = self.apply_double(word)
        mutations.update(double_variants)

        # Stage 2: Suffixes applied to base forms
        for base in [word, word.capitalize(), word.upper(), word.lower()]:
            for suffix in COMMON_SUFFIXES:
                mutations.add(base + suffix)

        # Stage 3: Leetspeak (single substitutions only for performance)
        leet_variants = self.apply_leet(word, max_variants=200)
        mutations.update(leet_variants)

        # Apply leet to capitalized form too
        cap_leet = self.apply_leet(word.capitalize(), max_variants=100)
        mutations.update(cap_leet)

        # Stage 4: Capitalized + suffixes (most common password pattern)
        for suffix in COMMON_SUFFIXES[:20]:  # Most common suffixes
            mutations.add(word.capitalize() + suffix)
            mutations.add(word.upper() + suffix)

        # Apply truncation
        mutations.update(self.apply_truncate(word))

        # Enforce max limit
        if len(mutations) > self.max_mutations:
            mutations = set(list(mutations)[:self.max_mutations])

        return mutations

    def apply_ruleset(self, word: str, rules: List[str]) -> Set[str]:
        """Apply a specific set of named rules.

        Args:
            word: Base word to mutate.
            rules: List of rule names to apply.
                   Options: caps, leet, suffix, prefix, reverse, double, truncate, all

        Returns:
            Set of mutated words.
        """
        results = set()

        if "all" in rules:
            return self.apply_all_rules(word)

        if "caps" in rules:
            results.update(self.apply_capitalization(word))

        if "leet" in rules:
            results.update(self.apply_leet(word))

        if "suffix" in rules:
            results.update(self.apply_suffix(word))

        if "prefix" in rules:
            results.update(self.apply_prefix(word))

        if "reverse" in rules:
            results.update(self.apply_reverse(word))

        if "truncate" in rules:
            results.update(self.apply_truncate(word))

        if "double" in rules:
            results.update(self.apply_double(word))

        if not results:
            results.add(word)

        return results


# ---------------------------------------------------------------------------
# Convenience functions
# ---------------------------------------------------------------------------

_engine = WordRuleEngine()


def generate_mutations(word: str, rules: Optional[List[str]] = None) -> List[str]:
    """Generate password mutations for a word.

    Args:
        word: Base word to mutate.
        rules: List of rules to apply. Default is all rules.

    Returns:
        Sorted list of unique mutations.
    """
    if rules:
        results = _engine.apply_ruleset(word, rules)
    else:
        results = _engine.apply_all_rules(word)
    return sorted(results)


def describe_rules() -> dict:
    """Return a description of all available rules."""
    return {
        "caps": "Capitalization variants (lower, UPPER, Capitalize, sWAP cASE, alternating)",
        "leet": "Leetspeak substitutions (a->@4, e->3, s->$5, i->1!, o->0, t->7+)",
        "suffix": "Common suffix patterns (years, numbers, special chars)",
        "prefix": "Common prefix patterns (!, #, the, My, super)",
        "reverse": "Reversed word variants",
        "truncate": "Truncated word variants (remove last 1-3 chars)",
        "double": "Doubled word variants (wordword)",
        "all": "All rules applied in combination stages",
    }
