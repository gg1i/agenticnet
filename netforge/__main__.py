"""Legacy module execution entry point (`python -m netforge`), delegating to AgenticNet."""

from __future__ import annotations

from agenticnet.cli import main

if __name__ == "__main__":
    raise SystemExit(main())
