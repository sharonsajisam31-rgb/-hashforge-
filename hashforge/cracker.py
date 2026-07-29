"""
Hash cracking engine with multiprocessing support.

Performs dictionary-based hash cracking with optional rule-based
word mutations for increased coverage.
"""

import time
import multiprocessing
from dataclasses import dataclass
from typing import Optional, Set, List, Callable
from concurrent.futures import ProcessPoolExecutor, as_completed


# ---------------------------------------------------------------------------
# Data types
# ---------------------------------------------------------------------------

@dataclass
class CrackResult:
    """Result of a hash cracking attempt."""
    found: bool
    password: str = ""
    hash_value: str = ""
    hash_type: str = ""
    attempts: int = 0
    time_taken: float = 0.0
    rule_used: str = ""
    words_tested: int = 0
    rate: float = 0.0  # hashes per second
    message: str = ""


# ---------------------------------------------------------------------------
# Cracking Engine
# ---------------------------------------------------------------------------

class HashCracker:
    """Dictionary-based hash cracker with rule engine integration."""

    def __init__(self, workers: Optional[int] = None):
        """Initialize the cracker.

        Args:
            workers: Number of worker processes. Defaults to CPU count.
        """
        self.workers = workers or multiprocessing.cpu_count()
        self._rule_engine = None  # Lazy import to avoid circular deps

    def _get_rule_engine(self):
        """Lazy import and init rule engine."""
        if self._rule_engine is None:
            from .rules import WordRuleEngine
            self._rule_engine = WordRuleEngine(max_mutations=50000)
        return self._rule_engine

    def crack_dictionary(
        self,
        hash_value: str,
        hash_type: str,
        wordlist_path: str,
        use_rules: bool = True,
        verbose: bool = False,
        progress_callback: Optional[Callable] = None,
    ) -> CrackResult:
        """Crack a hash using a dictionary wordlist.

        Args:
            hash_value: The target hash to crack.
            hash_type: Hash algorithm (md5, sha256, etc.).
            wordlist_path: Path to wordlist file (one word per line).
            use_rules: If True, apply mutation rules to each word.
            verbose: If True, print progress.
            progress_callback: Optional callback for progress updates.

        Returns:
            CrackResult with findings.
        """
        from .hasher import verify_hash, identify_hash_type

        if not hash_type:
            hash_type = identify_hash_type(hash_value)
            if not hash_type:
                return CrackResult(
                    found=False,
                    hash_value=hash_value,
                    message=f"Could not identify hash type for: {hash_value[:20]}..."
                )

        # Count lines in wordlist
        try:
            with open(wordlist_path, "r", encoding="utf-8", errors="ignore") as f:
                total_words = sum(1 for _ in f)
        except FileNotFoundError:
            return CrackResult(
                found=False,
                hash_value=hash_value,
                hash_type=hash_type,
                message=f"Wordlist not found: {wordlist_path}"
            )

        start_time = time.time()
        results = {"found": False, "password": ""}

        if self.workers > 1 and total_words > 10000:
            # Use multiprocessing for large wordlists
            result = self._crack_parallel(
                hash_value, hash_type, wordlist_path,
                total_words, use_rules, verbose
            )
        else:
            # Single process for small wordlists
            result = self._crack_single(
                hash_value, hash_type, wordlist_path,
                total_words, use_rules, verbose
            )

        elapsed = time.time() - start_time
        words_tested = result.get("attempts", 0)
        rate = words_tested / elapsed if elapsed > 0 else 0

        return CrackResult(
            found=result["found"],
            password=result["password"],
            hash_value=hash_value,
            hash_type=hash_type,
            attempts=result.get("attempts", 0),
            time_taken=round(elapsed, 2),
            rule_used=result.get("rule_used", ""),
            words_tested=words_tested,
            rate=round(rate, 0),
        )

    def _crack_single(
        self, hash_value: str, hash_type: str,
        wordlist_path: str, total_words: int,
        use_rules: bool, verbose: bool
    ) -> dict:
        """Single-process cracking."""
        from .hasher import verify_hash

        result = {"found": False, "password": "", "attempts": 0}

        engine = self._get_rule_engine() if use_rules else None

        with open(wordlist_path, "r", encoding="utf-8", errors="ignore") as f:
            for i, line in enumerate(f):
                word = line.strip()
                if not word:
                    continue

                # Report progress
                if verbose and i > 0 and i % 50000 == 0:
                    pct = (i / total_words) * 100
                    print(f"  Progress: {i:,}/{total_words:,} ({pct:.1f}%)")

                # Test the word itself
                result["attempts"] += 1
                if verify_hash(word, hash_value, hash_type):
                    result["found"] = True
                    result["password"] = word
                    result["rule_used"] = "none (exact match)"
                    return result

                # Test mutations
                if use_rules and engine:
                    mutations = engine.apply_all_rules(word)
                    # Limit to first 1000 mutations for speed
                    for mutated in list(mutations)[:1000]:
                        result["attempts"] += 1
                        if verify_hash(mutated, hash_value, hash_type):
                            result["found"] = True
                            result["password"] = mutated
                            result["rule_used"] = "rule-based mutation"
                            return result

        return result

    def _crack_parallel(
        self, hash_value: str, hash_type: str,
        wordlist_path: str, total_words: int,
        use_rules: bool, verbose: bool
    ) -> dict:
        """Multi-process cracking using worker pool."""
        # Read all words into chunks for workers
        all_words = []
        with open(wordlist_path, "r", encoding="utf-8", errors="ignore") as f:
            all_words = [line.strip() for line in f if line.strip()]

        if not all_words:
            return {"found": False, "password": "", "attempts": 0}

        chunk_size = max(1, len(all_words) // self.workers)
        chunks = [all_words[i:i+chunk_size]
                  for i in range(0, len(all_words), chunk_size)]

        found = multiprocessing.Event()
        found_password = multiprocessing.Array("c", b"\x00" * 256)
        attempts_counter = multiprocessing.Value("i", 0)

        processes = []
        for chunk in chunks:
            p = multiprocessing.Process(
                target=_parallel_worker,
                args=(chunk, hash_value, hash_type, use_rules,
                      found, found_password, attempts_counter)
            )
            processes.append(p)
            p.start()

        # Wait for completion or first found
        for p in processes:
            p.join(timeout=300)  # 5 min timeout per process

        # Cleanup
        for p in processes:
            if p.is_alive():
                p.terminate()
                p.join()

        password = found_password.value.decode("utf-8").rstrip("\x00")

        return {
            "found": found.is_set(),
            "password": password,
            "attempts": attempts_counter.value,
        }


# ---------------------------------------------------------------------------
# Module-level worker for multiprocessing (picklable on Windows)
# ---------------------------------------------------------------------------

def _parallel_worker(chunk_words, hash_val, hash_typ, use_rule,
                     found_event, found_pw, counter):
    """Worker function for parallel cracking. Must be at module level for Windows."""
    from .hasher import verify_hash
    from .rules import WordRuleEngine

    engine = WordRuleEngine(max_mutations=50000) if use_rule else None

    for word in chunk_words:
        if found_event.is_set():
            return

        with counter.get_lock():
            counter.value += 1

        if verify_hash(word, hash_val, hash_typ):
            found_event.set()
            try:
                found_pw.value = word.encode("utf-8")[:255]
            except Exception:
                found_pw.value = word.encode("utf-8", errors="replace")[:255]
            return

        if engine:
            mutations = engine.apply_all_rules(word)
            for mutated in list(mutations)[:1000]:
                if found_event.is_set():
                    return
                with counter.get_lock():
                    counter.value += 1
                if verify_hash(mutated, hash_val, hash_typ):
                    found_event.set()
                    try:
                        found_pw.value = mutated.encode("utf-8")[:255]
                    except Exception:
                        found_pw.value = mutated.encode("utf-8", errors="replace")[:255]
                    return


# ---------------------------------------------------------------------------
# Convenience function
# ---------------------------------------------------------------------------

def crack_hash(
    hash_value: str,
    hash_type: Optional[str] = None,
    wordlist_path: str = "",
    use_rules: bool = True,
    workers: Optional[int] = None,
) -> CrackResult:
    """Quick-access function for hash cracking.

    Args:
        hash_value: The hash to crack.
        hash_type: Hash algorithm (auto-detected if None).
        wordlist_path: Path to wordlist file.
        use_rules: Apply mutation rules.
        workers: Number of worker processes.

    Returns:
        CrackResult with findings.
    """
    cracker = HashCracker(workers=workers)
    return cracker.crack_dictionary(
        hash_value=hash_value,
        hash_type=hash_type or "",
        wordlist_path=wordlist_path,
        use_rules=use_rules,
    )
