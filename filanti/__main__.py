"""
Filanti v2 entry point.

Launches the REPL with: python -m filanti
Falls back to the legacy CLI with: python -m filanti --legacy
"""

import sys


def main() -> None:
    if "--legacy" in sys.argv:
        from filanti.cli.main import main as legacy_main
        legacy_main()
    else:
        from filanti.cli.repl import repl_main
        repl_main()


if __name__ == "__main__":
    main()

