# 🔨 HashForge

A powerful **hash cracking toolkit** with a built-in **rule-based word mutation engine** and **password strength analyzer**. Python CLI tool for security professionals and cybersecurity enthusiasts.

```
hashforge crack --hash "5d41402abc4b2a76b9719d911017c592" --wordlist rockyou.txt
hashforge analyze --password "MyP@ssw0rd2024!"
hashforge rules --word "password" --show 20
```

## 🚀 Quick Start

```bash
# Clone and install
cd hashforge
pip install -r requirements.txt

# Or install the package
pip install -e .

# Crack a hash
hashforge crack --hash "5d41402abc4b2a76b9719d911017c592" --wordlist words.txt

# Analyze a password
hashforge analyze --password "MyP@ssw0rd!"
```

Or use the `python -m` form:
```bash
python -m hashforge.cli crack --hash "..." --wordlist words.txt
```

## 🔥 Features

### 🎯 Hash Cracking
- **Dictionary attacks** with optional rule-based mutation engine
- **Multi-processing** support for fast cracking on multi-core systems
- **Hash auto-detection** by format/length
- **6 cracking methods**: exact match, capitalization, leetspeak, suffixes, prefixes, combinations

### 🔐 Supported Hash Types

| Type | Name | Length | Crack Speed* |
|------|------|--------|-------------|
| `md5` | MD5 | 32 hex | ~1 TH/s |
| `sha1` | SHA-1 | 40 hex | ~500 GH/s |
| `sha224` | SHA-224 | 56 hex | ~200 GH/s |
| `sha256` | SHA-256 | 64 hex | ~200 GH/s |
| `sha384` | SHA-384 | 96 hex | ~100 GH/s |
| `sha512` | SHA-512 | 128 hex | ~80 GH/s |
| `sha3_256` | SHA3-256 | 64 hex | ~50 GH/s |
| `sha3_512` | SHA3-512 | 128 hex | ~30 GH/s |
| `ntlm` | NTLM | 32 hex | ~10 TH/s |
| `bcrypt` | bcrypt | 60 chars | ~1 MH/s |

*\*Estimated hashes/second on RTX 4090 (hashcat benchmarks)*

### ⚙️ Rule Engine

The mutation engine transforms base words into thousands of variants using:

| Rule | Description | Examples |
|------|-------------|----------|
| **Capitalization** | Case variants | `password` → `Password`, `PASSWORD`, `pASSWORD` |
| **Leetspeak** | Character substitutions | `password` → `p@ssw0rd`, `p@$$w0rd` |
| **Suffixes** | Common append patterns | `password` → `password123`, `password2024!` |
| **Prefixes** | Common prepend patterns | `hello` → `!hello`, `thehello` |
| **Reversal** | Word reversals | `hello` → `olleh` |
| **Doubling** | Word repetition | `hello` → `hellohello` |
| **Truncation** | Remove trailing chars | `hello` → `hel`, `hell` |
| **Combinations** | Multi-rule stacking | `Password123`, `P@ssword!`, `HELLO2024` |

### 📊 Password Analysis

Get detailed strength reports for any password:

```
Score:      82/100  ████████████░░░░░░
Strength:   Very Strong
Entropy:    97.3 bits
Crack Time: 2.3 centuries (SHA-256)

Character Sets: a-z, A-Z, 0-9, !@#$%
Issues: None found ✓
```

## 💻 CLI Reference

### Commands

```
hashforge crack   --hash <hash> --wordlist <file>  Crack a hash
hashforge analyze --password <pass>                 Analyze password strength
hashforge rules   --word <word>                    Show word mutations
hashforge verify  --hash <hash> --password <pass>  Verify password against hash
hashforge hash    --text <text> --type <algo>       Compute hash of text
hashforge list                                      List supported hash types
```

### Options

| Option | Short | Description |
|--------|-------|-------------|
| `--hash HASH` | `-H` | Target hash value |
| `--wordlist FILE` | `-w` | Path to wordlist file |
| `--type TYPE` | `-t` | Hash type (auto-detected if omitted) |
| `--password PASS` | `-p` | Password to analyze/verify |
| `--no-rules` | | Disable rule-based mutations (faster) |
| `--workers N` | | Number of worker processes (default: CPU count) |
| `--show N` | | Number of mutations to display (default: 20) |
| `--rule RULE` | | Specific rule to apply (default: all) |
| `--text TEXT` | `-t` | Text to hash |
| `--type TYPE` | `-d` | Hash algorithm for `hash` command |

### Examples

```bash
# Basic hash cracking
hashforge crack --hash "5d41402abc4b2a76b9719d911017c592" --wordlist words.txt

# Specify hash type explicitly (skips auto-detection)
hashforge crack --hash "..." --wordlist words.txt --type sha256

# Fast mode (no rule mutations)
hashforge crack --hash "..." --wordlist words.txt --no-rules

# Password strength analysis
hashforge analyze --password "MyP@ssw0rd2024!"
hashforge analyze --password "123456"          # Very Weak - common password!

# Explore the rule engine
hashforge rules --word "password" --rule leet
hashforge rules --word "hello" --rule caps --show 10
hashforge rules --word "admin" --rule suffix --show 15

# Verify a password against a hash
hashforge verify --hash "5d41402abc4b2a76b9719d911017c592" --password "hello"

# Compute hashes
hashforge hash --text "Hello World" --type sha256
hashforge hash --text "secret" --type ntlm

# List all supported hash types
hashforge list
```

## 🐍 Python API

```python
from hashforge import (
    compute_hash, verify_hash, identify_hash_type,
    crack_hash, generate_mutations, analyze_password,
)

# Compute a hash
result = compute_hash("hello", "sha256")
print(result.hash_value)
# → 2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824

# Crack a hash (returns quickly for small wordlists)
result = crack_hash(
    hash_value="5d41402abc4b2a76b9719d911017c592",
    wordlist_path="words.txt",
    use_rules=True,
)
if result.found:
    print(f"Password: {result.password}")
    print(f"Method: {result.rule_used}")

# Generate word mutations
mutations = generate_mutations("password", rules=["caps", "leet"])
print(f"Generated {len(mutations)} variants")

# Analyze password strength
report = analyze_password("MyP@ssw0rd!")
print(f"Score: {report.score}/100 - {report.strength_label}")
print(f"Crack time: {report.estimated_crack_time}")
```

## 🧪 Running Tests

```bash
cd hashforge

# Run all tests (41 total)
python tests/test_hasher.py    # 14 tests
python tests/test_rules.py      # 11 tests
python tests/test_cracker.py    # 6 tests
python tests/test_analyzer.py   # 10 tests
```

## 📁 Project Structure

```
hashforge/
├── hashforge/
│   ├── __init__.py    # Package exports
│   ├── hasher.py      # Hash computation & verification
│   ├── rules.py       # Word mutation engine (leet/caps/suffixes)
│   ├── cracker.py     # Dictionary cracking with multiprocessing
│   ├── analyzer.py    # Password strength analysis
│   └── cli.py         # Command-line interface
├── tests/
│   ├── test_hasher.py     # 14 tests
│   ├── test_rules.py      # 11 tests
│   ├── test_cracker.py    # 6 tests
│   └── test_analyzer.py   # 10 tests
├── requirements.txt
├── pyproject.toml
├── .gitignore
└── README.md
```

## ⚠️ Legal & Ethical Use

HashForge is intended for **authorized security testing and educational purposes only**. Only use this tool on systems you own or have explicit written permission to test. Unauthorized use of password cracking tools may violate applicable laws.

## 📜 License

MIT — Use freely, modify as you wish.
