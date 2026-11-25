"""Verify forensic evidence integrity against SHA-256 manifest."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from src.common.evidence_manifest import verify_manifest


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Verify SHA-256 integrity of Operation Hydra evidence files."
    )
    parser.add_argument(
        "--evidence-dir",
        type=Path,
        default=ROOT_DIR / "evidence",
        help="Evidence directory to verify (default: evidence/).",
    )
    args = parser.parse_args()

    manifest_path = args.evidence_dir / "manifest.json"
    if not manifest_path.exists():
        print(f"[ERROR] Missing manifest: {manifest_path}", file=sys.stderr)
        return 1

    result = verify_manifest(args.evidence_dir, manifest_path)
    print(
        f"Evidence Integrity Check: {result.matched_count}/{result.checked_count} "
        f"files matched SHA-256 digests."
    )
    if result.mismatches:
        for item in result.mismatches:
            print(
                f"  [MISMATCH] {item['evidence_id']} ({item['relative_path']}): "
                f"expected {item['expected_sha256']} != actual {item['actual_sha256']}",
                file=sys.stderr,
            )
    if result.missing_files:
        for path in result.missing_files:
            print(f"  [MISSING] {path}", file=sys.stderr)
    if result.untracked_files:
        for path in result.untracked_files:
            print(f"  [UNTRACKED] {path}", file=sys.stderr)

    if not result.verified:
        print("[FAILED] Evidence integrity verification failed.", file=sys.stderr)
        return 1

    print("[VERIFIED] All evidence artifacts match their recorded SHA-256 hashes.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
