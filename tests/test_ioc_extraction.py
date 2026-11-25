"""Focused unit tests for malware telemetry classification, IOC extraction, and evidence integrity."""

from __future__ import annotations

import shutil
from pathlib import Path

from src.common.evidence_manifest import build_manifest, verify_manifest, write_manifest
from src.common.hashing import compute_sha256
from src.email_analysis.phishing_analyzer import analyze_email_directory
from src.malware_analysis.behavior_analyzer import analyze_simulated_behavior
from src.malware_analysis.ioc_extractor import extract_iocs
from src.malware_analysis.payload_decoder import decode_payload_fixture

ROOT_DIR = Path(__file__).resolve().parent.parent
EVIDENCE_DIR = ROOT_DIR / "evidence"
FIXTURE_PATH = (
    ROOT_DIR / "samples" / "malware" / "harmless-simulator" / "encoded_payload_fixture.txt"
)


def test_safe_fixture_decode_and_trojan_classification() -> None:
    decoded = decode_payload_fixture(FIXTURE_PATH)
    assert decoded["execution_performed"] is False
    assert decoded["decoded_payload"]["staging_domain"] == "pay-verify.asterionfin-verify.example"

    behavior = analyze_simulated_behavior(
        EVIDENCE_DIR / "endpoint" / "execution-events.json",
        EVIDENCE_DIR / "endpoint" / "malware-observations.json",
    )
    assert "Trojan" in behavior["primary_classification"]
    assert behavior["is_real_malware"] is False
    assert behavior["family_differentiation"]["Remote Access Trojan (RAT)"]["matches"] is False
    assert behavior["family_differentiation"]["Keylogger"]["matches"] is False
    assert behavior["family_differentiation"]["Logic Bomb"]["matches"] is False
    assert behavior["family_differentiation"]["Worm"]["matches"] is False


def test_ioc_extraction_deduplicates_and_marks_synthetic() -> None:
    emails = analyze_email_directory(EVIDENCE_DIR / "emails")
    decoded = decode_payload_fixture(FIXTURE_PATH)
    report = extract_iocs(
        email_findings=emails,
        execution_events_path=EVIDENCE_DIR / "endpoint" / "execution-events.json",
        malware_observations_path=EVIDENCE_DIR / "endpoint" / "malware-observations.json",
        connection_logs_path=EVIDENCE_DIR / "network" / "connection-logs.json",
        ip_observations_path=EVIDENCE_DIR / "network" / "ip-observations.csv",
        decoded_fixture=decoded,
    )

    assert report["total_iocs"] >= 15
    assert all(ioc["origin"] == "synthetic" for ioc in report["iocs"])
    keys = [(ioc["type"], ioc["value"]) for ioc in report["iocs"]]
    assert len(keys) == len(set(keys))
    assert ("ip", "203.0.113.95") in keys
    assert ("domain", "asteri0nfin.example") in keys


def test_evidence_integrity_detects_post_hash_tampering(tmp_path: Path) -> None:
    sample_dir = tmp_path / "evidence"
    (sample_dir / "emails").mkdir(parents=True)
    target = sample_dir / "emails" / "phishing-01.eml"
    shutil.copy2(EVIDENCE_DIR / "emails" / "phishing-01.eml", target)

    manifest = build_manifest(sample_dir)
    manifest_path = sample_dir / "manifest.json"
    write_manifest(manifest, manifest_path)

    original_hash = compute_sha256(target)
    assert verify_manifest(sample_dir, manifest_path).verified is True

    # Simulate unauthorized modification after hashing
    target.write_text(target.read_text(encoding="utf-8") + "\n# tampered\n", encoding="utf-8")
    tampered_result = verify_manifest(sample_dir, manifest_path)

    assert tampered_result.verified is False
    assert len(tampered_result.mismatches) == 1
    assert tampered_result.mismatches[0]["expected_sha256"] == original_hash
