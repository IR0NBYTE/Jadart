"""Entry point for `python3 -m jadart`.

`python3 -m jadart.cli` keeps working as well. Both land in the same main().
"""
from __future__ import annotations

from .cli import main

if __name__ == "__main__":
    raise SystemExit(main())
