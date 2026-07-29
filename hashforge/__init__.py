"""
HashForge - Hash cracking toolkit with rule engine and password analysis.

A comprehensive hash cracking toolkit supporting:
  - Multiple hash types: MD5, SHA-1/2/3, NTLM, bcrypt
  - Dictionary-based cracking with multiprocessing
  - Rule-based word mutation engine (leet, caps, suffixes)
  - Password strength analysis with entropy and crack-time estimation
"""

__version__ = "1.0.0"
__author__ = "HashForge"
__description__ = "Hash cracking toolkit with rule engine and password analysis"

from .hasher import (
    compute_hash,
    verify_hash,
    identify_hash_type,
    list_hash_types,
    HashResult,
)

from .cracker import (
    crack_hash,
    HashCracker,
    CrackResult,
)

from .rules import (
    generate_mutations,
    describe_rules,
    WordRuleEngine,
)

from .analyzer import (
    analyze_password,
    PasswordReport,
)

from .gpu_accel import (
    GPUCracker,
    get_gpu_info,
    gpu_benchmark,
    get_cracker,
    GPUInfo,
)

__all__ = [
    "compute_hash",
    "verify_hash",
    "identify_hash_type",
    "list_hash_types",
    "HashResult",
    "crack_hash",
    "HashCracker",
    "CrackResult",
    "generate_mutations",
    "describe_rules",
    "WordRuleEngine",
    "analyze_password",
    "PasswordReport",
    "GPUCracker",
    "get_gpu_info",
    "gpu_benchmark",
    "get_cracker",
    "GPUInfo",
]
