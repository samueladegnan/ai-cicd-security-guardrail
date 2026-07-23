"""MISRA C:2012 rules used for compliance triage."""

from __future__ import annotations

MISRA_C_RULES: dict[str, dict[str, object]] = {
    "Dir-1.1": {
        "title": "Dir-1.1 Any implementation-defined behaviour must be documented and understood",
        "description": "Avoid reliance on undefined or implementation-defined language behaviour.",
        "cwes": ["CWE-758"],
    },
    "Rule-1.3": {
        "title": "Rule-1.3 There shall be no occurrence of undefined or critical unspecified behaviour",
        "description": "Undefined behaviour must not occur.",
        "cwes": ["CWE-758"],
    },
    "Rule-7.4": {
        "title": "Rule-7.4 A string literal shall not be assigned to an object unless the object's type is 'pointer to const-qualified char'",
        "description": "String literals are read-only.",
        "cwes": ["CWE-770"],
    },
    "Rule-8.14": {
        "title": "Rule-8.14 The const qualifier shall be used to document read-only objects",
        "description": "Use const to declare read-only objects.",
        "cwes": ["CWE-770"],
    },
    "Rule-14.4": {
        "title": "Rule-14.4 The condition of an if-statement or iteration statement shall have essentially Boolean type",
        "description": "Boolean expressions must be explicit.",
        "cwes": ["CWE-840"],
    },
    "Rule-17.7": {
        "title": "Rule-17.7 The value returned by a function having non-void return type shall be used",
        "description": "Function return values must not be ignored.",
        "cwes": ["CWE-252"],
    },
    "Rule-18.1": {
        "title": "Rule-18.1 A pointer resulting from arithmetic on a pointer operand shall address an element of the same array or one past the last element",
        "description": "Pointer arithmetic must stay within array bounds.",
        "cwes": ["CWE-119", "CWE-125", "CWE-787"],
    },
    "Rule-18.2": {
        "title": "Rule-18.2 Subtraction between pointers shall only address elements of the same array",
        "description": "Pointer subtraction must be within the same array object.",
        "cwes": ["CWE-119", "CWE-125"],
    },
    "Rule-18.3": {
        "title": "Rule-18.3 The relational operators >, >=, < and <= shall not be applied to objects of pointer type except where they point into the same object",
        "description": "Relational pointer comparisons require same-object pointers.",
        "cwes": ["CWE-119", "CWE-125"],
    },
    "Rule-18.6": {
        "title": "Rule-18.6 The address of an object with automatic storage shall not be copied to another object that persists after the first object has ceased to exist",
        "description": "Avoid returning pointers to local variables.",
        "cwes": ["CWE-562"],
    },
    "Rule-20.7": {
        "title": "Rule-20.7 Expressions resulting from the expansion of macro parameters shall be enclosed in parentheses",
        "description": "Macro arguments must be parenthesized to avoid precedence issues.",
        "cwes": ["CWE-783"],
    },
    "Rule-21.1": {
        "title": "Rule-21.1 #define and #undef shall not be used on a reserved identifier or reserved macro name",
        "description": "Do not redefine reserved identifiers or macros.",
        "cwes": ["CWE-758"],
    },
    "Rule-21.3": {
        "title": "Rule-21.3 The memory allocation and deallocation functions of <stdlib.h> shall not be used",
        "description": "Dynamic memory can lead to non-deterministic behaviour.",
        "cwes": ["CWE-415", "CWE-416", "CWE-590"],
    },
    "Rule-21.4": {
        "title": "Rule-21.4 The standard header file <setjmp.h> shall not be used",
        "description": "setjmp/longjmp can break resource management.",
        "cwes": ["CWE-676"],
    },
    "Rule-21.6": {
        "title": "Rule-21.6 The Standard Library input/output functions shall not be used",
        "description": "Avoid unsafe I/O functions.",
        "cwes": ["CWE-676"],
    },
}