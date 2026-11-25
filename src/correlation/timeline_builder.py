"""Unified UTC timeline builder handling missing timestamps and uncertain ordering."""

from __future__ import annotations

import csv
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def normalize_utc_timestamp(value: Any) -> str | None:
    """Normalize an ISO-8601 timestamp string to canonical UTC ``YYYY-MM-DDTHH:MM:SSZ``."""
    if value is None:
        return None
    text = str(value).strip()
    if not text:
        return None
    try:
        dt = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def make_timeline_event(
    *,
    timestamp: Any,
    source_layer: str,
    stage: str,
    event_type: str,
    summary: str,
    evidence_ref: str,
    actors_or_entities: list[str] | None = None,
) -> dict[str, Any]:
    """Create a normalized timeline entry with explicit timestamp validity metadata."""
    normalized = normalize_utc_timestamp(timestamp)
    return {
        "timestamp_utc": normalized,
        "timestamp_status": "valid_utc" if normalized else "missing_or_unparseable",
        "source_layer": source_layer,
        "stage": stage,
        "event_type": event_type,
        "summary": summary,
        "evidence_ref": evidence_ref,
        "entities": actors_or_entities or [],
    }


def collect_events_from_evidence(
    *,
    email_findings: list[dict[str, Any]],
    dns_records_path: Path,
    connection_logs_path: Path,
    execution_events_path: Path,
    login_events_path: Path,
    transactions_path: Path,
    wallet_transfers_path: Path,
) -> list[dict[str, Any]]:
    """Gather raw events across all evidence layers for timeline correlation."""
    events: list[dict[str, Any]] = []

    dns_data = json.loads(dns_records_path.read_text(encoding="utf-8"))
    for domain, info in dns_data.get("domains", {}).items():
        if info.get("role") == "legitimate_target_organization":
            continue
        created = info.get("whois", {}).get("created_at")
        events.append(
            make_timeline_event(
                timestamp=created,
                source_layer="infrastructure_whois",
                stage="Reconnaissance & Staging",
                event_type="lookalike_domain_registered",
                summary=f"Synthetic lookalike domain '{domain}' registered ({info.get('role')}).",
                evidence_ref="dns-records.json",
                actors_or_entities=[domain],
            )
        )

    for email_item in email_findings:
        events.append(
            make_timeline_event(
                timestamp=email_item.get("timestamp_utc"),
                source_layer="email",
                stage="Phishing & Spoofing",
                event_type="phishing_email_delivered",
                summary=(
                    f"{email_item['sample_id']} delivered from '{email_item['sender']}' "
                    f"(SPF={email_item['spf']}, DMARC={email_item['dmarc']})."
                ),
                evidence_ref=email_item["filename"],
                actors_or_entities=[email_item["sender"], *email_item.get("recipient", [])],
            )
        )

    for conn in json.loads(connection_logs_path.read_text(encoding="utf-8")):
        events.append(
            make_timeline_event(
                timestamp=conn.get("timestamp"),
                source_layer="network",
                stage="Network Observation",
                event_type=conn.get("action", "network_connection"),
                summary=(
                    f"{conn['protocol']} connection {conn['src_ip']} -> {conn['dst_ip']}:{conn['dst_port']} "
                    f"({conn.get('action')})."
                ),
                evidence_ref=conn["conn_id"],
                actors_or_entities=[conn["src_ip"], conn["dst_ip"]],
            )
        )

    for ep in json.loads(execution_events_path.read_text(encoding="utf-8")):
        events.append(
            make_timeline_event(
                timestamp=ep.get("timestamp"),
                source_layer="endpoint_simulation",
                stage="Initial Compromise",
                event_type=ep["event"],
                summary=f"Host {ep['host']} ({ep['process']}): simulated event '{ep['event']}'.",
                evidence_ref=ep["event_id"],
                actors_or_entities=[ep["host"], ep["user_id"], ep["process"]],
            )
        )

    with login_events_path.open("r", encoding="utf-8") as handle:
        for row in csv.DictReader(handle):
            stage = "Unauthorized Access"
            if row["event_type"] == "payment_instruction_modified":
                stage = "Financial Fraud Initiation"
            elif row["event_type"] in {"incident_reported", "session_revoked"}:
                stage = "Detection & Response"
            elif row["source_ip"] == "192.0.2.50" and row["status"] == "SUCCESS":
                stage = "Normal Baseline"

            events.append(
                make_timeline_event(
                    timestamp=row.get("timestamp"),
                    source_layer="authentication",
                    stage=stage,
                    event_type=f"{row['event_type']}_{row['status'].lower()}",
                    summary=(
                        f"{row['user_id']} on {row['application']} from {row['source_ip']} "
                        f"({row['event_type']}={row['status']}; {row['notes']})."
                    ),
                    evidence_ref=row["event_id"],
                    actors_or_entities=[row["user_id"], row["source_ip"], row["session_id"]],
                )
            )

    with transactions_path.open("r", encoding="utf-8") as handle:
        for row in csv.DictReader(handle):
            events.append(
                make_timeline_event(
                    timestamp=row.get("timestamp"),
                    source_layer="financial_fiat",
                    stage="Financial Fraud & Layering",
                    event_type=f"fiat_transfer_{row['status'].lower()}",
                    summary=(
                        f"{row['transaction_id']} ({row['method']}): INR {row['amount']} "
                        f"{row['source']} -> {row['destination']} [{row['status']}]."
                    ),
                    evidence_ref=row["transaction_id"],
                    actors_or_entities=[row["source"], row["destination"], row["utr_reference"]],
                )
            )

    with wallet_transfers_path.open("r", encoding="utf-8") as handle:
        for row in csv.DictReader(handle):
            events.append(
                make_timeline_event(
                    timestamp=row.get("timestamp"),
                    source_layer="financial_crypto_sim",
                    stage="Simulated Crypto Conversion",
                    event_type="simulated_wallet_transfer",
                    summary=(
                        f"{row['transfer_id']}: {row['token_amount']} {row['token_symbol']} "
                        f"({row['source_wallet']} -> {row['destination_wallet']})."
                    ),
                    evidence_ref=row["transfer_id"],
                    actors_or_entities=[row["source_wallet"], row["destination_wallet"]],
                )
            )

    return events


def build_unified_timeline(events: list[dict[str, Any]]) -> dict[str, Any]:
    """Sort valid UTC events chronologically and isolate entries with missing timestamps."""
    valid_events = [e for e in events if e["timestamp_utc"] is not None]
    unsequenced = [e for e in events if e["timestamp_utc"] is None]

    # Deterministic tie-breaking on equal timestamps using source layer and evidence ref
    ordered = sorted(
        valid_events,
        key=lambda item: (item["timestamp_utc"], item["source_layer"], item["evidence_ref"]),
    )

    same_ts_collisions = sum(
        1
        for idx in range(1, len(ordered))
        if ordered[idx]["timestamp_utc"] == ordered[idx - 1]["timestamp_utc"]
    )

    def _first_ts(predicate: Any) -> str | None:
        for item in ordered:
            if predicate(item):
                return item["timestamp_utc"]
        return None

    def _last_ts(predicate: Any) -> str | None:
        for item in reversed(ordered):
            if predicate(item):
                return item["timestamp_utc"]
        return None

    compromise_start = _first_ts(lambda e: e["event_type"] == "attachment_opened")
    compromise_end = _first_ts(lambda e: e["event_type"] == "payment_instruction_modified_success")

    milestones = {
        "earliest_observed_event": ordered[0]["timestamp_utc"] if ordered else None,
        "initial_access_indicator": _first_ts(lambda e: e["event_type"] == "phishing_email_delivered"),
        "suspected_compromise_window": {
            "start_utc": compromise_start,
            "end_utc": compromise_end,
        },
        "financial_fraud_initiation": _first_ts(
            lambda e: e["event_type"] == "payment_instruction_modified_success"
        ),
        "fund_movement_window": {
            "start_utc": _first_ts(lambda e: e["source_layer"] == "financial_fiat"),
            "end_utc": _last_ts(lambda e: e["source_layer"] in {"financial_fiat", "financial_crypto_sim"}),
        },
        "detection_time": _first_ts(lambda e: e["event_type"] == "incident_reported_success"),
        "response_actions": [
            e["summary"] for e in ordered if e["stage"] == "Detection & Response"
        ],
    }

    return {
        "incident_id": "INC-2026-HYDRA-01",
        "total_events": len(events),
        "sequenced_event_count": len(ordered),
        "unsequenced_event_count": len(unsequenced),
        "uncertain_ordering": bool(unsequenced or same_ts_collisions > 0),
        "simultaneous_timestamp_count": same_ts_collisions,
        "milestones": milestones,
        "timeline": ordered,
        "unsequenced_events": unsequenced,
    }
