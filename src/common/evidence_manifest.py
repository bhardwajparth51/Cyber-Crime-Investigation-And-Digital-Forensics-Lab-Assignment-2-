"""Forensic evidence manifest generation, chain-of-custody, and verification."""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from src.common.hashing import compute_sha256

DEFAULT_ACQUIRED_AT = "2026-11-20T10:30:00Z"


@dataclass(frozen=True)
class EvidenceRecord:
    """Metadata and cryptographic digest for a single preserved evidence item."""

    evidence_id: str
    filename: str
    relative_path: str
    sha256: str
    size_bytes: int
    source: str
    acquired_at: str
    classification: str
    evidence_tier: str
    integrity_status: str


@dataclass(frozen=True)
class VerificationResult:
    """Outcome of verifying an evidence directory against its manifest."""

    verified: bool
    checked_count: int
    matched_count: int
    mismatches: list[dict[str, str]]
    missing_files: list[str]
    untracked_files: list[str]


def _classify_source(relative_path: str) -> str:
    """Map an evidence relative path to its forensic provenance source."""
    top_dir = relative_path.split("/", 1)[0]
    mapping = {
        "emails": "synthetic_mail_gateway",
        "headers": "synthetic_mail_gateway",
        "network": "synthetic_network_sensor",
        "endpoint": "synthetic_endpoint_simulator",
        "authentication": "synthetic_identity_provider",
        "financial": "synthetic_banking_ledger",
    }
    return mapping.get(top_dir, "synthetic_dataset")


def build_manifest(
    evidence_dir: Path,
    acquired_at: str = DEFAULT_ACQUIRED_AT,
    custodian: str = "Vikram Kulkarni (IR-Lead, Asterion SOC)",
) -> dict[str, Any]:
    """Scan original synthetic evidence files and build a deterministic manifest."""
    excluded = {"manifest.json", "chain-of-custody.json"}
    files = sorted(
        path
        for path in evidence_dir.rglob("*")
        if path.is_file() and path.name not in excluded
    )

    records: list[dict[str, Any]] = []
    for idx, file_path in enumerate(files, start=1):
        rel = file_path.relative_to(evidence_dir).as_posix()
        record = EvidenceRecord(
            evidence_id=f"EV-{idx:03d}",
            filename=file_path.name,
            relative_path=rel,
            sha256=compute_sha256(file_path),
            size_bytes=file_path.stat().st_size,
            source=_classify_source(rel),
            acquired_at=acquired_at,
            classification="synthetic",
            evidence_tier="original_synthetic",
            integrity_status="verified",
        )
        records.append(asdict(record))

    return {
        "incident_id": "INC-2026-HYDRA-01",
        "manifest_version": "1.0",
        "generated_at": acquired_at,
        "custodian": custodian,
        "disclaimer": (
            "All artifacts in this manifest belong to a controlled academic simulation "
            "and are not court-admissible evidence of a real-world crime."
        ),
        "evidence_count": len(records),
        "records": records,
    }


def write_manifest(manifest: dict[str, Any], manifest_path: Path) -> None:
    """Persist the manifest JSON to disk."""
    manifest_path.parent.mkdir(parents=True, exist_ok=True)
    manifest_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")


def build_chain_of_custody(
    manifest: dict[str, Any],
    acquired_at: str = DEFAULT_ACQUIRED_AT,
) -> dict[str, Any]:
    """Create a deterministic chain-of-custody log referencing manifest records."""
    events = [
        {
            "sequence": 1,
            "timestamp": acquired_at,
            "action": "ACQUIRED_AND_HASHED",
            "actor": manifest["custodian"],
            "location": "evidence/",
            "notes": (
                f"Preserved {manifest['evidence_count']} synthetic artifacts for "
                f"{manifest['incident_id']} with SHA-256 sealing."
            ),
        },
        {
            "sequence": 2,
            "timestamp": "2026-11-20T10:35:00Z",
            "action": "DERIVED_ANALYSIS_SEPARATION",
            "actor": "Operation Hydra Forensic Pipeline",
            "location": "reports/generated/",
            "notes": (
                "Read-only ingestion into analysis modules; derived outputs written "
                "exclusively under reports/generated/ to preserve original evidence."
            ),
        },
    ]
    return {
        "incident_id": manifest["incident_id"],
        "custodian": manifest["custodian"],
        "evidence_ids": [r["evidence_id"] for r in manifest["records"]],
        "custody_log": events,
    }


def verify_manifest(evidence_dir: Path, manifest_path: Path) -> VerificationResult:
    """Verify all files on disk against SHA-256 digests recorded in manifest.json."""
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    records = manifest.get("records", [])

    expected_paths: set[str] = set()
    mismatches: list[dict[str, str]] = []
    missing_files: list[str] = []
    matched_count = 0

    for record in records:
        rel_path = record["relative_path"]
        expected_paths.add(rel_path)
        target = evidence_dir / rel_path
        if not target.exists():
            missing_files.append(rel_path)
            continue

        actual_hash = compute_sha256(target)
        if actual_hash != record["sha256"]:
            mismatches.append(
                {
                    "evidence_id": record["evidence_id"],
                    "relative_path": rel_path,
                    "expected_sha256": record["sha256"],
                    "actual_sha256": actual_hash,
                }
            )
        else:
            matched_count += 1

    excluded = {"manifest.json", "chain-of-custody.json"}
    actual_paths = {
        path.relative_to(evidence_dir).as_posix()
        for path in evidence_dir.rglob("*")
        if path.is_file() and path.name not in excluded
    }
    untracked_files = sorted(actual_paths - expected_paths)

    verified = not mismatches and not missing_files and not untracked_files
    return VerificationResult(
        verified=verified,
        checked_count=len(records),
        matched_count=matched_count,
        mismatches=mismatches,
        missing_files=missing_files,
        untracked_files=untracked_files,
    )
