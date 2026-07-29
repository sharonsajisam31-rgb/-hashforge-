"""
CLI module for HashForge.

Provides command-line interface with commands:
  crack    - Crack a hash using dictionary + rules
  analyze  - Analyze password strength
  rules    - Show word mutations
  verify   - Verify password against a hash
  hash     - Compute hash of text
  list     - List supported hash types
"""

import argparse
import sys
import os
import time
from typing import Optional


# ---------------------------------------------------------------------------
# ANSI colors
# ---------------------------------------------------------------------------

class Colors:
    BLUE = "\033[94m"
    CYAN = "\033[96m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    RED = "\033[91m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    RESET = "\033[0m"
    MAGENTA = "\033[95m"


def _supports_color() -> bool:
    if os.name == "nt":
        try:
            import ctypes
            kernel32 = ctypes.windll.kernel32
            return kernel32.SetConsoleMode(kernel32.GetStdHandle(-11), 7) != 0
        except Exception:
            return False
    return hasattr(sys.stdout, "isatty") and sys.stdout.isatty()


USE_COLOR = _supports_color()


def c(text: str, color: str) -> str:
    if USE_COLOR:
        return f"{color}{text}{Colors.RESET}"
    return text


# ---------------------------------------------------------------------------
# Argument parser
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="hashforge",
        description="HashForge - Hash cracking toolkit with rule engine and password analysis",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  hashforge crack --hash \"5d41402abc4b2a76b9719d911017c592\" --wordlist rockyou.txt
  hashforge crack --hash \"...\" --wordlist words.txt --type sha256 --no-rules
  hashforge analyze --password \"MyP@ssw0rd2024!\"
  hashforge rules --word \"password\" --show 20
  hashforge hash --text \"Hello World\" --type md5
  hashforge verify --hash \"...\" --password \"mypass\" --type md5
  hashforge list
        """,
    )

    subparsers = parser.add_subparsers(dest="command", help="Command to execute")

    # --- crack ---
    crack_parser = subparsers.add_parser("crack", help="Crack a hash using dictionary attack")
    crack_parser.add_argument("--hash", "-H", required=True, help="Target hash value")
    crack_parser.add_argument("--wordlist", "-w", required=True, help="Path to wordlist file")
    crack_parser.add_argument("--type", "-t", dest="hash_type", default="",
                              help="Hash type (auto-detected if omitted)")
    crack_parser.add_argument("--no-rules", action="store_true",
                              help="Disable rule-based mutations")
    crack_parser.add_argument("--workers", type=int, default=0,
                              help="Number of worker processes (default: CPU count)")
    crack_parser.add_argument("--gpu", action="store_true",
                              help="Use GPU acceleration (for MD5/SHA-256)")
    crack_parser.add_argument("--output", "-o", default="",
                              help="Save results to file (results.txt)")

    # --- analyze ---
    analyze_parser = subparsers.add_parser("analyze", help="Analyze password strength")
    analyze_parser.add_argument("--password", "-p", required=True, help="Password to analyze")

    # --- rules ---
    rules_parser = subparsers.add_parser("rules", help="Show word mutations from rules")
    rules_parser.add_argument("--word", "-w", required=True, help="Base word to mutate")
    rules_parser.add_argument("--show", type=int, default=20,
                              help="Number of mutations to show (default: 20)")
    rules_parser.add_argument("--rule", default="all",
                              choices=["caps", "leet", "suffix", "prefix",
                                       "reverse", "truncate", "double", "all"],
                              help="Rule to apply (default: all)")

    # --- verify ---
    verify_parser = subparsers.add_parser("verify", help="Verify password against a hash")
    verify_parser.add_argument("--hash", "-H", required=True, help="Hash to compare against")
    verify_parser.add_argument("--password", "-p", required=True, help="Password to verify")
    verify_parser.add_argument("--type", "-t", dest="hash_type", default="",
                               help="Hash type (auto-detected if omitted)")

    # --- hash ---
    hash_parser = subparsers.add_parser("hash", help="Compute hash of text")
    hash_parser.add_argument("--text", "-t", required=True, help="Text to hash")
    hash_parser.add_argument("--type", "-d", default="md5",
                             choices=["md5", "sha1", "sha224", "sha256", "sha384",
                                      "sha512", "sha3_224", "sha3_256", "sha3_384",
                                      "sha3_512", "ntlm", "bcrypt"],
                             help="Hash algorithm (default: md5)")
    hash_parser.add_argument("--rounds", type=int, default=12,
                             help="bcrypt salt rounds (default: 12, range: 4-31)")

    # --- benchmark ---
    bench_parser = subparsers.add_parser("benchmark", help="Benchmark GPU/CPU hash rate")
    bench_parser.add_argument("--type", "-t", default="md5", dest="hash_type",
                              choices=["md5", "sha256"],
                              help="Hash algorithm to benchmark (default: md5)")
    bench_parser.add_argument("--words", "-n", type=int, default=50000,
                              help="Number of test words (default: 50000)")
    bench_parser.add_argument("--gpu", action="store_true",
                              help="Force GPU benchmark (falls back to CPU if no GPU)")

    # --- gpu-info ---
    subparsers.add_parser("gpu-info", help="Show GPU detection and hardware info")

    # --- list ---
    subparsers.add_parser("list", help="List supported hash types")

    return parser


# ---------------------------------------------------------------------------
# Command handlers
# ---------------------------------------------------------------------------

def cmd_crack(args: argparse.Namespace):
    """Crack a hash using dictionary attack."""
    from .cracker import HashCracker
    from .hasher import identify_hash_type

    hash_value = args.hash.strip()
    hash_type = args.hash_type if args.hash_type else identify_hash_type(hash_value)
    wordlist = args.wordlist
    use_rules = not args.no_rules
    workers = args.workers if args.workers > 0 else None
    use_gpu = args.gpu

    # Validate wordlist
    if not os.path.isfile(wordlist):
        print(c(f"[!] Wordlist not found: {wordlist}", Colors.RED))
        sys.exit(1)

    # Show crack header
    print()
    print(c("+================================================+", Colors.MAGENTA))
    if use_gpu:
        print(c(f"|  HASHFORGE CRACKER  [GPU ACCELERATED]                      |", Colors.MAGENTA))
    else:
        print(c(f"|  HASHFORGE CRACKER                                     |", Colors.MAGENTA))
    print(c("+================================================+", Colors.MAGENTA))
    print()
    print(f"  Target:   {c(hash_value[:48] + ('...' if len(hash_value) > 48 else ''), Colors.YELLOW)}")
    print(f"  Type:     {c(hash_type or 'Unknown', Colors.CYAN)}")
    print(f"  Wordlist: {c(os.path.relpath(wordlist), Colors.DIM)}")
    print(f"  Rules:    {c('Enabled' if use_rules else 'Disabled', Colors.GREEN if use_rules else Colors.RED)}")

    if use_gpu:
        from .gpu_accel import get_gpu_info
        gpu = get_gpu_info()
        if gpu.available:
            print(f"  GPU:      {c(gpu.device_name, Colors.MAGENTA)}")
            print(f"  VRAM:     {c(f'{gpu.memory_total_gb} GB', Colors.BLUE)}")
        else:
            print(f"  GPU:      {c('Not available (falling back to CPU)', Colors.YELLOW)}")
    else:
        print(f"  Workers:  {c(str(workers or os.cpu_count()), Colors.BLUE)}")
    print()

    if not hash_type:
        print(c("[!] Could not identify hash type. Use --type to specify.", Colors.RED))
        print(c(f"    Supported types: md5, sha1, sha256, sha512, ntlm, bcrypt, ...", Colors.YELLOW))
        sys.exit(1)

    # Count wordlist
    try:
        with open(wordlist, "r", encoding="utf-8", errors="ignore") as f:
            total = sum(1 for _ in f)
        print(f"  Dictionary: {c(f'{total:,}', Colors.BOLD)} words")
        if use_rules:
            print(f"  (with rules, each word may generate 50-500+ mutations)")
        print()
    except Exception as e:
        print(c(f"[!] Error reading wordlist: {e}", Colors.RED))
        sys.exit(1)

    # Run crack (with Ctrl+C handling)
    result_attr = None
    try:
        if use_gpu:
            from .gpu_accel import GPUCracker
            gpu_cracker = GPUCracker(batch_size=10000)
            if gpu_cracker.available:
                # Read all words
                all_words = []
                with open(wordlist, "r", encoding="utf-8", errors="ignore") as f:
                    all_words = [line.strip() for line in f if line.strip()]

                print(c(f"  GPU Cracking {len(all_words):,} words via {gpu_cracker.device_name}...", Colors.YELLOW))

                from .rules import WordRuleEngine
                engine = WordRuleEngine(max_mutations=50000) if use_rules else None

                start = time.time()
                found, password, attempts = gpu_cracker.crack_batch(
                    all_words, hash_value, hash_type, use_rules_engine=engine
                )
                elapsed = time.time() - start

                # Build result
                if found:
                    result_attr = {"found": True, "password": password,
                                   "attempts": attempts, "time_taken": round(elapsed, 2),
                                   "rule_used": "GPU direct match" if password in all_words else "GPU + rules"}
                else:
                    result_attr = {"found": False, "password": "",
                                   "attempts": attempts, "time_taken": round(elapsed, 2),
                                   "rule_used": ""}
            else:
                print(c("  GPU not available, falling back to CPU...", Colors.YELLOW))

        if result_attr is None:
            # CPU fallback
            cracker = HashCracker(workers=workers)
            print(c("  Cracking...", Colors.YELLOW))

            result = cracker.crack_dictionary(
                hash_value=hash_value,
                hash_type=hash_type,
                wordlist_path=wordlist,
                use_rules=use_rules,
                verbose=True,
            )
            result_attr = {
                "found": result.found,
                "password": result.password,
                "attempts": result.attempts,
                "time_taken": result.time_taken,
                "rule_used": result.rule_used,
            }

    except KeyboardInterrupt:
        print()
        print(c("\n[!] Cracking interrupted by user (Ctrl+C)", Colors.YELLOW))
        if result_attr is None:
            result_attr = {"found": False, "password": "", "attempts": 0, "time_taken": 0, "rule_used": ""}
        print()

    # Show results
    print()
    print(c("+------------------------------------------------+", Colors.CYAN))
    print(c("  RESULTS", Colors.BOLD))
    print(c("+------------------------------------------------+", Colors.CYAN))

    if result_attr["found"]:
        print(c(f"  [FOUND] PASSWORD FOUND!", Colors.GREEN + Colors.BOLD))
        print(f"     Password: {c(result_attr['password'], Colors.GREEN + Colors.BOLD)}")
        print(f"     Method:   {result_attr['rule_used']}")
    else:
        print(c(f"  [MISS] Password not found", Colors.RED))
        print(f"     Try a larger wordlist or enable rules.")

    print(f"  Attempts: {result_attr['attempts']:,}")
    print(f"  Time:     {result_attr['time_taken']:.2f}s")
    if result_attr['time_taken'] > 0:
        rate = result_attr['attempts'] / result_attr['time_taken']
        print(f"  Rate:     {rate:,.0f} hashes/sec")
    print()

    # Save to output file if requested
    if args.output:
        try:
            output_path = args.output
            with open(output_path, "w") as f:
                f.write("HashForge Crack Results\n")
                f.write("=" * 40 + "\n")
                f.write(f"Target Hash: {hash_value}\n")
                f.write(f"Hash Type:   {hash_type}\n")
                f.write(f"Wordlist:    {wordlist}\n")
                f.write(f"Rules:       {'Enabled' if use_rules else 'Disabled'}\n")
                f.write(f"Found:       {result_attr['found']}\n")
                if result_attr['found']:
                    f.write(f"Password:    {result_attr['password']}\n")
                    f.write(f"Method:      {result_attr['rule_used']}\n")
                f.write(f"Attempts:    {result_attr['attempts']:,}\n")
                f.write(f"Time:        {result_attr['time_taken']:.2f}s\n")
            print(c(f"  [OK] Results saved to: {output_path}", Colors.GREEN))
            print()
        except Exception as e:
            print(c(f"[!] Could not save results: {e}", Colors.RED))
            print()


def cmd_analyze(args: argparse.Namespace):
    """Analyze password strength."""
    from .analyzer import analyze_password, CRACK_TIME_DISCLAIMER

    password = args.password
    report = analyze_password(password)

    print()
    print(c("+================================================+", Colors.CYAN))
    print(c("|  PASSWORD STRENGTH ANALYSIS                              |", Colors.CYAN))
    print(c("+================================================+", Colors.CYAN))
    print()

    # Strength score with visual bar
    score_color = Colors.GREEN if report.score >= 60 else (Colors.YELLOW if report.score >= 40 else Colors.RED)
    bar_len = 20
    filled = int(report.score / 100 * bar_len)
    bar = "#" * filled + "-" * (bar_len - filled)
    print(f"  Score:      {c(f'{report.score}/100', score_color + Colors.BOLD)} {c(bar, score_color)}")
    print(f"  Strength:   {c(report.strength_label, score_color + Colors.BOLD)}")
    print()

    # Basic info
    print(f"  {c('Length:', Colors.BOLD):16s} {report.length}")
    print(f"  {c('Entropy:', Colors.BOLD):16s} {report.entropy_bits:.1f} bits")
    print(f"  {c('Crack Time:', Colors.BOLD):16s} {c(report.estimated_crack_time, Colors.YELLOW)} (SHA-256)")
    print(c(f"  {CRACK_TIME_DISCLAIMER}", Colors.DIM))
    print()

    # Character sets
    set_names = {
        "lowercase": "a-z", "uppercase": "A-Z",
        "digits": "0-9", "special": "!@#$%",
        "space": "' '"
    }
    sets_str = ", ".join(set_names.get(s, s) for s in report.character_sets) or "None"
    print(f"  {c('Character Sets:', Colors.BOLD)} {sets_str}")
    print()

    # Issues
    if report.issues:
        print(f"  {c('Issues:', Colors.RED + Colors.BOLD)}")
        for issue in report.issues:
            print(f"    {c('!', Colors.RED)} {issue}")
        print()

    # Suggestions
    if report.suggestions:
        print(f"  {c('Suggestions:', Colors.YELLOW + Colors.BOLD)}")
        for suggestion in report.suggestions[:5]:
            print(f"    {c('>', Colors.YELLOW)} {suggestion}")
        print()


def cmd_rules(args: argparse.Namespace):
    """Show word mutations from rules."""
    from .rules import generate_mutations, describe_rules

    word = args.word
    show_count = args.show
    rule = args.rule

    rules_desc = describe_rules()

    print()
    print(c("+================================================+", Colors.MAGENTA))
    print(c("|  RULE ENGINE - Word Mutations                              |", Colors.MAGENTA))
    print(c("+================================================+", Colors.MAGENTA))
    print()

    print(f"  Base word: {c(word, Colors.BOLD + Colors.YELLOW)}")
    print(f"  Rule:      {c(rule, Colors.CYAN)} - {rules_desc.get(rule, '')}")
    print()

    mutations = generate_mutations(word, rules=[rule] if rule != "all" else None)
    total = len(mutations)

    if total == 0:
        print(c("  No mutations generated.", Colors.YELLOW))
        return

    print(f"  Generated {c(f'{total:,}', Colors.BOLD)} mutations")
    print()

    # Show sample
    print(c(f"  Sample (first {min(show_count, total)}):", Colors.BOLD))
    for i, mutation in enumerate(mutations[:show_count], 1):
        marker = "->" if mutation != word else "  "
        print(f"    {marker} {mutation}")
    print()

    if total > show_count:
        print(c(f"  ... and {total - show_count} more", Colors.DIM))
        print()


def cmd_verify(args: argparse.Namespace):
    """Verify password against a hash."""
    from .hasher import verify_hash, identify_hash_type

    hash_value = args.hash.strip()
    password = args.password
    hash_type = args.hash_type if args.hash_type else identify_hash_type(hash_value)

    if not hash_type:
        print(c("[!] Could not identify hash type. Use --type to specify.", Colors.RED))
        sys.exit(1)

    print()
    print(c("+================================================+", Colors.CYAN))
    print(c("|  HASH VERIFICATION                                      |", Colors.CYAN))
    print(c("+================================================+", Colors.CYAN))
    print()

    print(f"  {c('Hash:', Colors.BOLD):12s} {hash_value[:48]}{'...' if len(hash_value) > 48 else ''}")
    print(f"  {c('Type:', Colors.BOLD):12s} {hash_type}")
    print(f"  {c('Password:', Colors.BOLD):12s} {password}")
    print()

    result = verify_hash(password, hash_value, hash_type)

    if result:
        print(c("  [OK] MATCH! Password is correct.", Colors.GREEN + Colors.BOLD))
    else:
        print(c("  [NO] No match. Password is incorrect.", Colors.RED))

    print()


def cmd_hash(args: argparse.Namespace):
    """Compute hash of text."""
    from .hasher import compute_hash

    text = args.text
    hash_type = args.type

    result = compute_hash(text, hash_type, rounds=args.rounds)

    print()
    print(c("+================================================+", Colors.CYAN))
    print(c("|  HASH COMPUTATION                                        |", Colors.CYAN))
    print(c("+================================================+", Colors.CYAN))
    print()

    print(f"  {c('Algorithm:', Colors.BOLD):12s} {result.hash_type.upper()}")
    print(f"  {c('Input:', Colors.BOLD):12s} {text[:60]}{'...' if len(text) > 60 else ''}")
    print()

    if result.success:
        print(c(f"  {result.hash_type.upper()} Hash:", Colors.BOLD))
        print(f"  {c(result.hash_value, Colors.GREEN)}")
    else:
        print(c(f"  Error: {result.message}", Colors.RED))

    print()


def cmd_list():
    """List supported hash types."""
    from .hasher import list_hash_types

    hash_types = list_hash_types()

    print()
    print(c("+================================================+", Colors.CYAN))
    print(c("|  SUPPORTED HASH TYPES                                    |", Colors.CYAN))
    print(c("+================================================+", Colors.CYAN))
    print()

    print(f"  {'Type':<12} {'Hex Length':12} {'Name':20}")
    print(f"  " + "-" * 44)
    for htype in hash_types:
        from .hasher import HASH_INFO
        info = HASH_INFO.get(htype)
        if info:
            length = info["length"]
            name = info["name"]
        elif htype == "bcrypt":
            length = 60
            name = "bcrypt"
        else:
            length = "-"
            name = htype.upper()
        print(f"  {c(htype, Colors.CYAN):<12} {str(length):>12} {name:>20}")

    print()
    print(c("  Tip: hash type is auto-detected by length for hex hashes.", Colors.DIM))
    print()


# ---------------------------------------------------------------------------
# GPU Commands
# ---------------------------------------------------------------------------

def cmd_benchmark(args: argparse.Namespace):
    """Benchmark GPU/CPU hash cracking speed."""
    from .gpu_accel import GPUCracker, gpu_benchmark

    print()
    print(c("+================================================+", Colors.MAGENTA))
    print(c("|  HASHFORGE BENCHMARK                                    |", Colors.MAGENTA))
    print(c("+================================================+", Colors.MAGENTA))
    print()

    if args.gpu:
        cracker = GPUCracker(batch_size=args.words)
        if not cracker.available:
            print(c("  [WARNING] No GPU detected. Running CPU benchmark instead.", Colors.YELLOW))
        print(f"  Device:    {cracker.device_name}")
    else:
        print(f"  Device:    CPU ({os.cpu_count()} cores)")

    print(f"  Algorithm: {c(args.hash_type.upper(), Colors.CYAN)}")
    print(f"  Words:     {c(f'{args.words:,}', Colors.BOLD)}")
    print()

    print(c("  Running benchmark...", Colors.YELLOW))

    result = gpu_benchmark(hash_type=args.hash_type, num_words=args.words)

    print(c("  Done!\n", Colors.GREEN))

    print(f"  {c('Results:', Colors.BOLD)}")
    print(f"  {'Time:':16s} {result['time_seconds']:.3f}s")
    print(f"  {'Hash Rate:':16s} {c(result['rate_human'], Colors.GREEN + Colors.BOLD)}")
    print(f"  {'Device:':16s} {result['device']}")
    print(f"  {'GPU Mode:':16s} {'Yes' if result['gpu_accelerated'] else 'No'}")
    print()


def cmd_gpu_info():
    """Show GPU detection and hardware information."""
    from .gpu_accel import get_gpu_info

    print()
    print(c("+================================================+", Colors.CYAN))
    print(c("|  GPU DETECTION                                         |", Colors.CYAN))
    print(c("+================================================+", Colors.CYAN))
    print()

    gpu = get_gpu_info()

    if gpu.available:
        print(f"  {c('Status:', Colors.GREEN + Colors.BOLD):20s} {c('AVAILABLE', Colors.GREEN)}")
        print(f"  {'Device:':20s} {gpu.device_name}")
        print(f"  {'CUDA Version:':20s} {gpu.cuda_version}")
        print(f"  {'Compute Capability:':20s} {gpu.compute_capability}")
        print(f"  {'VRAM:':20s} {gpu.memory_total_gb} GB")
        print(f"  {'Multi-Processors:':20s} {gpu.multi_processor_count}")

        from .gpu_accel import GPUCracker
        gpu_cracker = GPUCracker()
        print(f"  {'GPU Cracking:':20s} {c('Ready', Colors.GREEN)}")
        print(f"  {'Supported:':20s} MD5 (SHA-256 uses CPU fallback)")
    else:
        print(f"  {c('Status:', Colors.RED + Colors.BOLD):20s} {c('NOT AVAILABLE', Colors.RED)}")
        if gpu.error:
            print(f"  {'Reason:':20s} {gpu.error}")
        print()
        print(c("  GPU acceleration requires:", Colors.YELLOW))
        print(f"    {c('1.', Colors.BOLD)} NVIDIA GPU with CUDA Compute 3.5+")
        print(f"    {c('2.', Colors.BOLD)} pip install numba")
        print(f"    {c('3.', Colors.BOLD)} NVIDIA CUDA Toolkit 11.x+")

    print()


# ---------------------------------------------------------------------------
# Main dispatch
# ---------------------------------------------------------------------------

def run_command(args: argparse.Namespace):
    """Dispatch to the appropriate command handler."""
    if args.command == "crack":
        cmd_crack(args)
    elif args.command == "analyze":
        cmd_analyze(args)
    elif args.command == "rules":
        cmd_rules(args)
    elif args.command == "verify":
        cmd_verify(args)
    elif args.command == "hash":
        cmd_hash(args)
    elif args.command == "list":
        cmd_list()
    elif args.command == "benchmark":
        cmd_benchmark(args)
    elif args.command == "gpu-info":
        cmd_gpu_info()
    else:
        print(c("[!] No command specified. Use --help for usage.", Colors.YELLOW))
        sys.exit(1)


def main():
    """Main entry point for HashForge CLI."""
    parser = build_parser()
    args = parser.parse_args()

    if args.command is None:
        parser.print_help()
        print()
        print(c("Tip: Use 'hashforge list' to see supported hash types.", Colors.YELLOW))
        print(c("     Use 'hashforge crack --help' for cracking options.", Colors.YELLOW))
        sys.exit(0)

    run_command(args)


if __name__ == "__main__":
    main()
