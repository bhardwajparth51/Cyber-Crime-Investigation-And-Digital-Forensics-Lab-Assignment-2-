"""Cross-source evidence correlation and conclusion traceability table."""

from __future__ import annotations

from typing import Any


def build_evidence_correlation(
    *,
    email_findings: list[dict[str, Any]],
    malware_analysis: dict[str, Any],
    financial_impact: dict[str, Any],
    mule_reports: list[dict[str, Any]],
    timeline_report: dict[str, Any],
) -> dict[str, Any]:
    """Link high-level forensic conclusions to multi-source supporting evidence."""
    email_ids = [e["sample_id"] for e in email_findings]
    high_risk_mules = [
        m["account_id"] for m in mule_reports if "mule" in m["classification"]
    ]
    milestones = timeline_report["milestones"]

    relationships = [
        {
            "conclusion_id": "CONC-01",
            "conclusion": "Targeted phishing & lookalike domain infrastructure impersonated Asterion Financial.",
            "supporting_sources": ["emails", "headers", "network/dns-records.json"],
            "supporting_artifacts": email_ids + ["asteri0nfin.example", "asterionfin-verify.example"],
            "confidence": "high (within synthetic simulation)",
            "caveat": "Email authentication failures come from embedded synthetic headers, not live DNS verification.",
        },
        {
            "conclusion_id": "CONC-02",
            "conclusion": "Simulated decoy invoice interaction preceded simulated credential-profile access and outbound beacon.",
            "supporting_sources": ["endpoint/execution-events.json", "network/connection-logs.json"],
            "supporting_artifacts": ["EVT-EP-001", "EVT-EP-004", "EVT-EP-005", "CONN-004"],
            "confidence": "high (within synthetic simulation)",
            "caveat": "Temporal proximity does not independently prove causal credential exfiltration without memory forensics.",
        },
        {
            "conclusion_id": "CONC-03",
            "conclusion": "Compromised employee session from external IP 203.0.113.95 modified payment instructions.",
            "supporting_sources": ["authentication/login-events.csv", "network/ip-observations.csv"],
            "supporting_artifacts": ["AUTH-002..AUTH-005", "SES-9941-HYDRA", "AUTH-006", "CONN-005"],
            "confidence": "high (within synthetic simulation)",
            "caveat": "Logs establish account/session misuse from 203.0.113.95, not the physical identity of the operator.",
        },
        {
            "conclusion_id": "CONC-04",
            "conclusion": (
                f"INR {financial_impact['total_fraudulent_outflow_inr']:,.2f} left victim account; "
                f"INR {financial_impact['frozen_recoverable_inr']:,.2f} frozen across mule tiers, "
                f"INR {financial_impact['unrecovered_loss_inr']:,.2f} routed to simulated crypto conversion."
            ),
            "supporting_sources": [
                "financial/transactions.csv",
                "financial/account-ledger.csv",
                "financial/wallet-transfers.csv",
            ],
            "supporting_artifacts": ["TXN-001..TXN-005", *high_risk_mules, "WLT-SIM-001", "WLT-SIM-002"],
            "confidence": "high (within synthetic simulation)",
            "caveat": "Simulated wallet hops use fictional identifiers and do not attribute ownership to real persons.",
        },
        {
            "conclusion_id": "CONC-05",
            "conclusion": (
                f"Incident detected at {milestones['detection_time']} and contained via session revocation and bank holds."
            ),
            "supporting_sources": ["authentication/login-events.csv", "financial/transactions.csv"],
            "supporting_artifacts": ["AUTH-007", "AUTH-008", "TXN-005"],
            "confidence": "high (within synthetic simulation)",
            "caveat": "Rapid SOC escalation preserved partial funds; statutory CERT-In 6-hour reporting applies on detection.",
        },
    ]

    return {
        "incident_id": "INC-2026-HYDRA-01",
        "correlation_principle": (
            "Multi-source event correlation reconstructs probable attack sequence; "
            "temporal correlation alone is never presented as conclusive legal proof of individual guilt."
        ),
        "malware_classification": malware_analysis["primary_classification"],
        "relationship_table": relationships,
    }
