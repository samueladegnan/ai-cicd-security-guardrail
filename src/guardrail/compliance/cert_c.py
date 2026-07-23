"""CERT C secure coding rules used for compliance triage."""

from __future__ import annotations

CERT_C_RULES: dict[str, dict[str, object]] = {
    "PRE00-C": {
        "title": "PRE00-C. Avoid making assumptions about precedence and associativity",
        "description": "Expressions should not rely on undefined operator precedence.",
        "cwes": ["CWE-783"],
    },
    "EXP00-C": {
        "title": "EXP00-C. Use parentheses for precedence",
        "description": "Do not depend on C's precedence rules.",
        "cwes": ["CWE-783"],
    },
    "STR30-C": {
        "title": "STR30-C. Do not attempt to modify string literals",
        "description": "String literals may be stored in read-only memory.",
        "cwes": ["CWE-770"],
    },
    "STR31-C": {
        "title": "STR31-C. Guarantee that storage for strings has sufficient space",
        "description": "Ensure that string operations do not overflow buffers.",
        "cwes": ["CWE-120", "CWE-121", "CWE-122"],
    },
    "STR32-C": {
        "title": "STR32-C. Do not pass a non-null-terminated character sequence to a function that expects a string",
        "description": "Passing unterminated sequences can lead to buffer over-reads.",
        "cwes": ["CWE-126", "CWE-170"],
    },
    "STR38-C": {
        "title": "STR38-C. Do not confuse functions that accept a wchar_t argument with those that accept a char argument",
        "description": "Use the correct character width for string functions.",
        "cwes": ["CWE-843"],
    },
    "ARR30-C": {
        "title": "ARR30-C. Do not form or use out-of-bounds pointers or array subscripts",
        "description": "Array accesses must remain within the bounds of the object.",
        "cwes": ["CWE-119", "CWE-125", "CWE-787"],
    },
    "ARR32-C": {
        "title": "ARR32-C. Ensure size arguments are appropriate for the array",
        "description": "When passing sizes to memory or string functions, ensure they match the destination.",
        "cwes": ["CWE-131", "CWE-806"],
    },
    "INT30-C": {
        "title": "INT30-C. Ensure that unsigned integer operations do not wrap",
        "description": "Unsigned integer wraparound can cause unexpected behavior.",
        "cwes": ["CWE-190", "CWE-680"],
    },
    "INT32-C": {
        "title": "INT32-C. Ensure that integer operations do not result in overflow or wraparound",
        "description": "Integer overflow can lead to memory corruption or logic errors.",
        "cwes": ["CWE-190", "CWE-680"],
    },
    "MEM30-C": {
        "title": "MEM30-C. Do not access freed memory",
        "description": "Use-after-free can lead to crashes or arbitrary code execution.",
        "cwes": ["CWE-416"],
    },
    "MEM31-C": {
        "title": "MEM31-C. Free dynamically allocated memory exactly once",
        "description": "Double-free can corrupt heap metadata and enable exploitation.",
        "cwes": ["CWE-415"],
    },
    "MEM34-C": {
        "title": "MEM34-C. Only free memory allocated dynamically",
        "description": "Freeing non-heap pointers is undefined behavior.",
        "cwes": ["CWE-590"],
    },
    "FIO37-C": {
        "title": "FIO37-C. Ensure that string arguments are null-terminated",
        "description": "File and string I/O require null-terminated buffers.",
        "cwes": ["CWE-170"],
    },
    "ERR34-C": {
        "title": "ERR34-C. Detect errors when converting a string to an integer",
        "description": "Check return values and errno after strtol/strtoul.",
        "cwes": ["CWE-676", "CWE-681"],
    },
    "MSC37-C": {
        "title": "MSC37-C. Ensure that control never reaches the end of a non-void function",
        "description": "Non-void functions must return a value on every path.",
        "cwes": ["CWE-758"],
    },
}