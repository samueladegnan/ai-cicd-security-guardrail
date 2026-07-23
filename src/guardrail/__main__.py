"""Entry point for `python -m guardrail`."""

from __future__ import annotations

import sys

from guardrail.cli import main

if __name__ == "__main__":
    sys.exit(main())