"""Verify byte-protected test inputs against their recorded SHA-256 hashes.

Usage (any OS, from anywhere): python3 scripts/verify_protected_inputs.py

The manifest (scripts/protected-inputs.json) records the CRLF bytes that
.gitattributes checks out on every OS. A working tree created before that
pin may still hold the same content with LF endings; that is accepted only
when the file contains no CR at all and its CRLF form matches exactly, and
it is reported so the checkout can be refreshed. Exit status is non-zero on
any missing or differing file, or on an empty manifest.
"""
import hashlib
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "scripts" / "protected-inputs.json"


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def main() -> int:
    manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
    files = manifest.get("files", {})
    if not files:
        print("FAIL: protected-input manifest lists no files")
        return 1
    failures, lf_checkouts = [], []
    for name, expected in sorted(files.items()):
        path = ROOT.joinpath(*name.split("/"))
        if not path.is_file():
            failures.append(f"missing  {name}")
            continue
        data = path.read_bytes()
        if sha256(data) == expected:
            continue
        if b"\r" not in data and sha256(data.replace(b"\n", b"\r\n")) == expected:
            lf_checkouts.append(name)
            continue
        failures.append(f"differs  {name}")
    for line in failures:
        print(f"FAIL: {line}")
    if lf_checkouts:
        print(
            f"note: {len(lf_checkouts)} file(s) have LF endings in this working tree but "
            "match their pinned CRLF form; refresh the checkout to restore exact bytes"
        )
    verdict = "FAIL" if failures else "PASS"
    print(f"{verdict}: {len(files) - len(failures)}/{len(files)} protected inputs match the record")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
