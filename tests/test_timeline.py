"""Focused unit tests for unified UTC timeline ordering and missing timestamp handling."""

from __future__ import annotations

from pathlib import Path

from src.correlation.timeline_builder import (
    build_unified_timeline,
    collect_events_from_evidence,
    make_timeline_event,
)
from src.email_analysis.phishing_analyzer import analyze_email_directory

ROOT_DIR = Path(__file__).resolve().parent.parent
EVIDENCE_DIR = ROOT_DIR / "evidence"


def test_unified_timeline_is_chronologically_ordered() -> None:
    emails = analyze_email_directory(EVIDENCE_DIR / "emails")
    events = collect_events_from_evidence(
        email_findings=emails,
        dns_records_path=EVIDENCE_DIR / "network" / "dns-records.json",
        connection_logs_path=EVIDENCE_DIR / "network" / "connection-logs.json",
        execution_events_path=EVIDENCE_DIR / "endpoint" / "execution-events.json",
        login_events_path=EVIDENCE_DIR / "authentication" / "login-events.csv",
        transactions_path=EVIDENCE_DIR / "financial" / "transactions.csv",
        wallet_transfers_path=EVIDENCE_DIR / "financial" / "wallet-transfers.csv",
    )
    timeline_report = build_unified_timeline(events)

    timestamps = [item["timestamp_utc"] for item in timeline_report["timeline"]]
    assert timestamps == sorted(timestamps)
    assert timeline_report["unsequenced_event_count"] == 0
    assert timeline_report["milestones"]["earliest_observed_event"] == "2026-11-16T04:12:00Z"
    assert timeline_report["milestones"]["financial_fraud_initiation"] == "2026-11-20T09:41:00Z"
    assert timeline_report["milestones"]["detection_time"] == "2026-11-20T10:15:00Z"


def test_missing_timestamps_are_isolated_as_uncertain() -> None:
    events = [
        make_timeline_event(
            timestamp="2026-11-20T09:00:00+05:30",
            source_layer="email",
            stage="Phishing",
            event_type="sample_event",
            summary="Normalized from IST to UTC.",
            evidence_ref="EV-TEST-1",
        ),
        make_timeline_event(
            timestamp="",
            source_layer="endpoint",
            stage="Compromise",
            event_type="missing_ts_event",
            summary="Event lacking timestamp.",
            evidence_ref="EV-TEST-2",
        ),
    ]
    report = build_unified_timeline(events)

    assert report["sequenced_event_count"] == 1
    assert report["timeline"][0]["timestamp_utc"] == "2026-11-20T03:30:00Z"
    assert report["unsequenced_event_count"] == 1
    assert report["uncertain_ordering"] is True
    assert report["unsequenced_events"][0]["timestamp_status"] == "missing_or_unparseable"
