#!/usr/bin/env python
"""Idempotent CLI to build/refresh the ChromaDB knowledge base.

Loads OWASP Top 10 (markdown), CWE (XML) and MITRE ATT&CK (STIX JSON) sources,
chunks them into documents with stable ids, and upserts them into Chroma so
re-running this script is always safe.

Implemented in Phase 3 alongside `app/infrastructure/ingestion/`.

Usage (once implemented):
    python -m scripts.ingest_knowledge --source owasp,cwe,attack
"""

from __future__ import annotations

import argparse
import sys


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--source",
        default="owasp,cwe,attack",
        help="Comma-separated list of sources to ingest.",
    )
    parser.parse_args()

    print("Knowledge ingestion is implemented in Phase 3.", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
