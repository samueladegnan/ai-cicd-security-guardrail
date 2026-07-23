"""FIPS 140-3 and federal security policy rules used for triage."""

from __future__ import annotations

FIPS_RULES: dict[str, dict[str, object]] = {
    "FIPS-CRYPTO-1": {
        "title": "Approved cryptographic algorithms only",
        "description": "Use only FIPS 140-3 approved algorithms (e.g., AES, SHA-2, ECDSA).",
        "cwes": ["CWE-327"],
    },
    "FIPS-CRYPTO-2": {
        "title": "Deterministic random bit generators (DRBG) must be used correctly",
        "description": "Use a FIPS-approved DRBG and seed it with sufficient entropy.",
        "cwes": ["CWE-338"],
    },
    "FIPS-CRYPTO-3": {
        "title": "Key zeroization and protection",
        "description": "Cryptographic keys must be zeroized when no longer needed.",
        "cwes": ["CWE-226", "CWE-316"],
    },
    "FIPS-AUTH-1": {
        "title": "Identity and authentication controls",
        "description": "Authenticate operators before performing cryptographic operations.",
        "cwes": ["CWE-287"],
    },
    "FIPS-INTEGRITY-1": {
        "title": "Software/firmware integrity",
        "description": "Maintain integrity of cryptographic module software and firmware.",
        "cwes": ["CWE-354", "CWE-494"],
    },
    "FIPS-POWER-1": {
        "title": "Mitigate environmental failure and power analysis",
        "description": "Protect against side-channel and environmental failure attacks.",
        "cwes": ["CWE-208"],
    },
}