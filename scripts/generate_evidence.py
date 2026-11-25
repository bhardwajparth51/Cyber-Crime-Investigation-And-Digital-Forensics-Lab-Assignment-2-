"""Deterministic synthetic evidence generator for Operation Hydra.

Generates synthetic email, header, network, endpoint, authentication, and
financial evidence under ``evidence/`` and seals them with a SHA-256 manifest
and chain-of-custody log. By default, refuses to overwrite existing original
evidence files unless ``--force`` is explicitly supplied.
"""

from __future__ import annotations

import argparse
import base64
import csv
import importlib.util
import json
import sys
from email.message import EmailMessage
from pathlib import Path
from typing import Any

ROOT_DIR = Path(__file__).resolve().parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from src.common.evidence_manifest import (
    DEFAULT_ACQUIRED_AT,
    build_chain_of_custody,
    build_manifest,
    write_manifest,
)

SIMULATOR_PATH = ROOT_DIR / "samples" / "malware" / "harmless-simulator" / "simulator.py"
FIXTURE_PATH = (
    ROOT_DIR / "samples" / "malware" / "harmless-simulator" / "encoded_payload_fixture.txt"
)


def _load_simulator_module() -> Any:
    """Load the harmless malware simulator module from samples/."""
    spec = importlib.util.spec_from_file_location("harmless_simulator", SIMULATOR_PATH)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Unable to load simulator at {SIMULATOR_PATH}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _build_eml(
    *,
    from_addr: str,
    reply_to: str,
    return_path: str,
    to_addr: str,
    subject: str,
    date_hdr: str,
    message_id: str,
    received_headers: list[str],
    auth_results: str,
    body_text: str,
    attachment_name: str | None = None,
    attachment_bytes: bytes | None = None,
    attachment_maintype: str = "application",
    attachment_subtype: str = "octet-stream",
) -> str:
    """Construct a deterministic RFC 5322 email string with synthetic headers."""
    msg = EmailMessage()
    msg["Return-Path"] = f"<{return_path}>"
    for rcv in received_headers:
        msg["Received"] = rcv
    msg["Authentication-Results"] = auth_results
    msg["From"] = from_addr
    msg["Reply-To"] = reply_to
    msg["To"] = to_addr
    msg["Subject"] = subject
    msg["Date"] = date_hdr
    msg["Message-ID"] = message_id
    msg["X-Simulation-Notice"] = "SYNTHETIC_ACADEMIC_EVIDENCE_OPERATION_HYDRA"
    msg.set_content(body_text)

    if attachment_name and attachment_bytes is not None:
        msg.add_attachment(
            attachment_bytes,
            maintype=attachment_maintype,
            subtype=attachment_subtype,
            filename=attachment_name,
        )
    return msg.as_string()


def _extract_raw_headers(eml_content: str) -> str:
    """Extract only the top-level RFC 5322 header block from an EML string."""
    header_block, _, _ = eml_content.partition("\n\n")
    return header_block.rstrip() + "\n"


def _write_csv(path: Path, fieldnames: list[str], rows: list[dict[str, Any]]) -> None:
    """Write deterministic CSV output with Unix line endings."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames, lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)


def _generate_emails_and_headers(evidence_dir: Path) -> None:
    """Create three synthetic phishing .eml samples and matching header files."""
    emails_dir = evidence_dir / "emails"
    headers_dir = evidence_dir / "headers"
    emails_dir.mkdir(parents=True, exist_ok=True)
    headers_dir.mkdir(parents=True, exist_ok=True)

    decoy_html = (
        b"<!-- SYNTHETIC DECOY ATTACHMENT: OPERATION HYDRA SIMULATION -->\n"
        b"<html><body><p>Simulated invoice portal redirect: "
        b"https://pay-verify.asterionfin-verify.example/invoice/8841</p></body></html>\n"
    )
    decoy_zip_stub = (
        b"SIMULATED-ARCHIVE-HEADER|OPERATION-HYDRA|"
        b"CONTAINS-SIMULATED-DECOY:invoice_viewer.exe|"
        b"TARGET:https://cdn.asteri0nfin.example/viewer/remittance\n"
    )

    samples = [
        (
            "phishing-01.eml",
            "email-01-headers.txt",
            _build_eml(
                from_addr="Asterion Billing Desk <billing@asteri0nfin.example>",
                reply_to="settlement-desk@asterion-billing.invalid",
                return_path="bounce-8841@asteri0nfin.example",
                to_addr="rohan.deshmukh@asterionfin.example",
                subject="URGENT: Overdue Vendor Invoice INV-2026-8841 Verification Required",
                date_hdr="Fri, 20 Nov 2026 08:42:10 +0000",
                message_id="<inv-8841-hydra@asteri0nfin.example>",
                received_headers=[
                    "from mail.asterionfin.example (192.0.2.10) by mx.asterionfin.example with ESMTPS id hydra01; Fri, 20 Nov 2026 08:42:10 +0000",
                    "from relay01.asteri0nfin.example (198.51.100.42) by mail.asterionfin.example with ESMTP id ext01; Fri, 20 Nov 2026 08:42:08 +0000",
                ],
                auth_results=(
                    "mx.asterionfin.example; "
                    "spf=fail (simulated: 198.51.100.42 not authorized for asterionfin.example) smtp.mailfrom=asteri0nfin.example; "
                    "dkim=none (simulated: no signature present); "
                    "dmarc=fail (simulated: p=reject policy alignment failed) header.from=asteri0nfin.example"
                ),
                body_text=(
                    "Dear Rohan,\n\n"
                    "Please review and verify the overdue vendor settlement INV-2026-8841 "
                    "before the 10:00 AM payment cutoff.\n"
                    "Portal link: https://pay-verify.asterionfin-verify.example/invoice/8841\n"
                    "Open the attached verification document to confirm beneficiary details.\n\n"
                    "Regards,\nAccounts & Vendor Billing Desk (Simulated)\n"
                ),
                attachment_name="Vendor_Invoice_INV-2026-8841.pdf.html",
                attachment_bytes=decoy_html,
                attachment_maintype="text",
                attachment_subtype="html",
            ),
        ),
        (
            "phishing-02.eml",
            "email-02-headers.txt",
            _build_eml(
                from_addr="Asterion Finance Ops <finance-ops@asterionfin.example>",
                reply_to="ops-clearance@asterion-billing.invalid",
                return_path="bounce@asterion-billing.invalid",
                to_addr="rohan.deshmukh@asterionfin.example",
                subject="Action Needed: November Payment Remittance Batch Re-validation",
                date_hdr="Fri, 20 Nov 2026 08:55:40 +0000",
                message_id="<remit-20261120@asterion-billing.invalid>",
                received_headers=[
                    "from mail.asterionfin.example (192.0.2.10) by mx.asterionfin.example with ESMTPS id hydra02; Fri, 20 Nov 2026 08:55:40 +0000",
                    "from mailout.asterion-billing.invalid (203.0.113.77) by mail.asterionfin.example with ESMTP id ext02; Fri, 20 Nov 2026 08:55:37 +0000",
                ],
                auth_results=(
                    "mx.asterionfin.example; "
                    "spf=softfail (simulated: 203.0.113.77 mismatch for header From asterionfin.example) smtp.mailfrom=asterion-billing.invalid; "
                    "dkim=fail (simulated: body hash mismatch) header.d=asterionfin.example; "
                    "dmarc=fail (simulated: alignment failed) header.from=asterionfin.example"
                ),
                body_text=(
                    "Hi Rohan,\n\n"
                    "The morning remittance batch failed checksum validation. "
                    "Download the attached batch package or validate online at:\n"
                    "https://cdn.asteri0nfin.example/viewer/remittance\n\n"
                    "Thanks,\nFinance Operations (Simulated)\n"
                ),
                attachment_name="Payment_Remittance_Batch_Nov20.zip",
                attachment_bytes=decoy_zip_stub,
                attachment_maintype="application",
                attachment_subtype="zip",
            ),
        ),
        (
            "phishing-03.eml",
            "email-03-headers.txt",
            _build_eml(
                from_addr="Asterion Audit Desk <audit-desk@asterionfin-verify.example>",
                reply_to="audit-desk@asterionfin-verify.example",
                return_path="audit-desk@asterionfin-verify.example",
                to_addr="meera.nair@asterionfin.example",
                subject="Revised Vendor Bank Mandate Approval - Immediate Sign-off",
                date_hdr="Fri, 20 Nov 2026 09:04:15 +0000",
                message_id="<mandate-7721@asterionfin-verify.example>",
                received_headers=[
                    "from mail.asterionfin.example (192.0.2.10) by mx.asterionfin.example with ESMTPS id hydra03; Fri, 20 Nov 2026 09:04:15 +0000",
                    "from portal-mx.asterionfin-verify.example (198.51.100.88) by mail.asterionfin.example with ESMTP id ext03; Fri, 20 Nov 2026 09:04:12 +0000",
                ],
                auth_results=(
                    "mx.asterionfin.example; "
                    "spf=pass (simulated: 198.51.100.88 listed in lookalike domain SPF) smtp.mailfrom=asterionfin-verify.example; "
                    "dkim=pass (simulated: signed by lookalike domain key) header.d=asterionfin-verify.example; "
                    "dmarc=none (simulated: no DMARC record published for lookalike domain)"
                ),
                body_text=(
                    "Dear Meera,\n\n"
                    "Vendor Apex Logistics has updated its settlement account details. "
                    "Please approve mandate reference PAY-REQ-7721 using the verification portal:\n"
                    "https://pay-verify.asterionfin-verify.example/vendor-mandate\n\n"
                    "Note: This unsolicited bulk-style notice requires action within 30 minutes.\n"
                    "Regards,\nInternal Audit & Compliance (Simulated)\n"
                ),
            ),
        ),
    ]

    for eml_name, hdr_name, eml_text in samples:
        (emails_dir / eml_name).write_text(eml_text, encoding="utf-8")
        (headers_dir / hdr_name).write_text(_extract_raw_headers(eml_text), encoding="utf-8")


def _generate_network_evidence(evidence_dir: Path) -> None:
    """Create synthetic DNS/WHOIS records, connection logs, and IP observations."""
    net_dir = evidence_dir / "network"
    net_dir.mkdir(parents=True, exist_ok=True)

    dns_records = {
        "classification": "synthetic",
        "disclaimer": "Reserved RFC 2606 domains and RFC 5737 TEST-NET IPs only.",
        "domains": {
            "asterionfin.example": {
                "role": "legitimate_target_organization",
                "a": ["192.0.2.10", "192.0.2.25"],
                "aaaa": ["2001:db8:10::10"],
                "mx": ["10 mail.asterionfin.example"],
                "txt": ["v=spf1 ip4:192.0.2.0/24 -all"],
                "spf": "v=spf1 ip4:192.0.2.0/24 -all",
                "dkim_selectors": {"s1._domainkey.asterionfin.example": "v=DKIM1; k=rsa; p=SIMULATED_KEY_LEGIT"},
                "dmarc": "v=DMARC1; p=reject; rua=mailto:dmarc@asterionfin.example",
                "whois": {
                    "registrar": "Simulated National Registry India",
                    "created_at": "2019-03-14T00:00:00Z",
                    "updated_at": "2026-03-14T00:00:00Z",
                    "registrant_org": "Asterion Financial Services Pvt. Ltd.",
                    "country": "IN",
                },
            },
            "asteri0nfin.example": {
                "role": "attacker_lookalike_homoglyph",
                "a": ["198.51.100.42"],
                "aaaa": [],
                "mx": ["10 relay01.asteri0nfin.example"],
                "txt": ["v=spf1 ip4:198.51.100.42 ~all"],
                "spf": "v=spf1 ip4:198.51.100.42 ~all",
                "dkim_selectors": {},
                "dmarc": None,
                "whois": {
                    "registrar": "Simulated Offshore Registrar",
                    "created_at": "2026-11-16T04:12:00Z",
                    "updated_at": "2026-11-16T04:12:00Z",
                    "registrant_org": "REDACTED FOR PRIVACY (Synthetic)",
                    "country": "ZZ",
                },
            },
            "asterion-billing.invalid": {
                "role": "attacker_spoofed_reply_domain",
                "a": ["203.0.113.77"],
                "aaaa": [],
                "mx": ["10 mailout.asterion-billing.invalid"],
                "txt": ["v=spf1 ip4:203.0.113.77 -all"],
                "spf": "v=spf1 ip4:203.0.113.77 -all",
                "dkim_selectors": {},
                "dmarc": None,
                "whois": {
                    "registrar": "Simulated Offshore Registrar",
                    "created_at": "2026-11-17T09:00:00Z",
                    "updated_at": "2026-11-17T09:00:00Z",
                    "registrant_org": "REDACTED FOR PRIVACY (Synthetic)",
                    "country": "ZZ",
                },
            },
            "asterionfin-verify.example": {
                "role": "attacker_spoofed_portal_domain",
                "a": ["198.51.100.88"],
                "aaaa": [],
                "mx": ["10 portal-mx.asterionfin-verify.example"],
                "txt": ["v=spf1 ip4:198.51.100.88 -all"],
                "spf": "v=spf1 ip4:198.51.100.88 -all",
                "dkim_selectors": {
                    "hydra._domainkey.asterionfin-verify.example": "v=DKIM1; k=rsa; p=SIMULATED_KEY_LOOKALIKE"
                },
                "dmarc": None,
                "whois": {
                    "registrar": "Simulated Offshore Registrar",
                    "created_at": "2026-11-18T11:30:00Z",
                    "updated_at": "2026-11-18T11:30:00Z",
                    "registrant_org": "REDACTED FOR PRIVACY (Synthetic)",
                    "country": "ZZ",
                },
            },
        },
    }
    (net_dir / "dns-records.json").write_text(
        json.dumps(dns_records, indent=2) + "\n", encoding="utf-8"
    )

    connection_logs = [
        {
            "conn_id": "CONN-001",
            "timestamp": "2026-11-20T08:42:08Z",
            "src_ip": "198.51.100.42",
            "dst_ip": "192.0.2.10",
            "dst_port": 25,
            "protocol": "SMTP",
            "host": "mail.asterionfin.example",
            "action": "delivered_phishing_01",
            "source": "simulation",
        },
        {
            "conn_id": "CONN-002",
            "timestamp": "2026-11-20T08:55:37Z",
            "src_ip": "203.0.113.77",
            "dst_ip": "192.0.2.10",
            "dst_port": 25,
            "protocol": "SMTP",
            "host": "mail.asterionfin.example",
            "action": "delivered_phishing_02",
            "source": "simulation",
        },
        {
            "conn_id": "CONN-003",
            "timestamp": "2026-11-20T09:04:12Z",
            "src_ip": "198.51.100.88",
            "dst_ip": "192.0.2.10",
            "dst_port": 25,
            "protocol": "SMTP",
            "host": "mail.asterionfin.example",
            "action": "delivered_phishing_03",
            "source": "simulation",
        },
        {
            "conn_id": "CONN-004",
            "timestamp": "2026-11-20T09:15:22Z",
            "src_ip": "192.0.2.50",
            "dst_ip": "198.51.100.88",
            "dst_port": 443,
            "protocol": "HTTPS",
            "domain": "pay-verify.asterionfin-verify.example",
            "action": "simulated_beacon_observed",
            "source": "simulation",
        },
        {
            "conn_id": "CONN-005",
            "timestamp": "2026-11-20T09:22:30Z",
            "src_ip": "203.0.113.95",
            "dst_ip": "192.0.2.25",
            "dst_port": 443,
            "protocol": "HTTPS",
            "domain": "pay.asterionfin.example",
            "action": "anomalous_external_portal_session",
            "source": "simulation",
        },
    ]
    (net_dir / "connection-logs.json").write_text(
        json.dumps(connection_logs, indent=2) + "\n", encoding="utf-8"
    )

    _write_csv(
        net_dir / "ip-observations.csv",
        ["ip_address", "range_type", "role", "simulated_reputation", "confidence", "first_seen", "notes"],
        [
            {
                "ip_address": "192.0.2.10",
                "range_type": "RFC5737-TEST-NET-1",
                "role": "corporate_mail_gateway",
                "simulated_reputation": "benign_internal",
                "confidence": "high",
                "first_seen": "2026-11-20T08:42:10Z",
                "notes": "Asterion Financial internal MX",
            },
            {
                "ip_address": "192.0.2.25",
                "range_type": "RFC5737-TEST-NET-1",
                "role": "corporate_payment_portal",
                "simulated_reputation": "benign_internal",
                "confidence": "high",
                "first_seen": "2026-11-20T09:18:10Z",
                "notes": "Asterion Financial payment approval portal",
            },
            {
                "ip_address": "192.0.2.50",
                "range_type": "RFC5737-TEST-NET-1",
                "role": "corporate_workstation_nat",
                "simulated_reputation": "benign_internal",
                "confidence": "high",
                "first_seen": "2026-11-20T08:30:00Z",
                "notes": "Corporate office NAT for WKS-FIN-104",
            },
            {
                "ip_address": "198.51.100.42",
                "range_type": "RFC5737-TEST-NET-2",
                "role": "phishing_smtp_relay",
                "simulated_reputation": "suspicious_simulated",
                "confidence": "high",
                "first_seen": "2026-11-20T08:42:08Z",
                "notes": "Relay for lookalike domain asteri0nfin.example",
            },
            {
                "ip_address": "203.0.113.77",
                "range_type": "RFC5737-TEST-NET-3",
                "role": "phishing_smtp_relay",
                "simulated_reputation": "suspicious_simulated",
                "confidence": "high",
                "first_seen": "2026-11-20T08:55:37Z",
                "notes": "Relay for spoofed sender asterion-billing.invalid",
            },
            {
                "ip_address": "198.51.100.88",
                "range_type": "RFC5737-TEST-NET-2",
                "role": "spoofed_portal_and_staging",
                "simulated_reputation": "malicious_simulated",
                "confidence": "high",
                "first_seen": "2026-11-20T09:04:12Z",
                "notes": "Hosts pay-verify.asterionfin-verify.example",
            },
            {
                "ip_address": "203.0.113.95",
                "range_type": "RFC5737-TEST-NET-3",
                "role": "unauthorized_login_source",
                "simulated_reputation": "malicious_simulated",
                "confidence": "high",
                "first_seen": "2026-11-20T09:18:10Z",
                "notes": "External IP executing brute-force/credential replay login",
            },
        ],
    )


def _generate_endpoint_evidence(evidence_dir: Path) -> None:
    """Create synthetic endpoint telemetry and decoded fixture observations."""
    endpoint_dir = evidence_dir / "endpoint"
    endpoint_dir.mkdir(parents=True, exist_ok=True)

    sim = _load_simulator_module()
    sim.write_simulation_output(endpoint_dir / "execution-events.json")

    encoded_b64 = FIXTURE_PATH.read_text(encoding="utf-8").strip()
    decoded_fixture = json.loads(base64.b64decode(encoded_b64).decode("utf-8"))

    observations = {
        "sample_metadata": sim.SIMULATED_SAMPLE_METADATA,
        "decoded_fixture_preview": decoded_fixture,
        "observed_capabilities": {
            "deceptive_invoice_lure": True,
            "simulated_credential_profile_access": True,
            "simulated_outbound_beacon": True,
            "persistent_remote_shell_observed": False,
            "keystroke_capture_observed": False,
            "time_or_logic_trigger_observed": False,
            "self_replication_observed": False,
        },
        "source": "simulation",
    }
    (endpoint_dir / "malware-observations.json").write_text(
        json.dumps(observations, indent=2) + "\n", encoding="utf-8"
    )


def _generate_authentication_evidence(evidence_dir: Path) -> None:
    """Create synthetic authentication and payment-portal session logs."""
    auth_dir = evidence_dir / "authentication"
    _write_csv(
        auth_dir / "login-events.csv",
        [
            "event_id",
            "timestamp",
            "user_id",
            "email",
            "source_ip",
            "session_id",
            "application",
            "event_type",
            "status",
            "notes",
        ],
        [
            {
                "event_id": "AUTH-001",
                "timestamp": "2026-11-20T08:30:00Z",
                "user_id": "EMP-FIN-104",
                "email": "rohan.deshmukh@asterionfin.example",
                "source_ip": "192.0.2.50",
                "session_id": "SES-4401-CORP",
                "application": "pay.asterionfin.example",
                "event_type": "login",
                "status": "SUCCESS",
                "notes": "Normal corporate office login",
            },
            {
                "event_id": "AUTH-002",
                "timestamp": "2026-11-20T09:18:10Z",
                "user_id": "EMP-FIN-104",
                "email": "rohan.deshmukh@asterionfin.example",
                "source_ip": "203.0.113.95",
                "session_id": "NONE",
                "application": "pay.asterionfin.example",
                "event_type": "login",
                "status": "FAILED",
                "notes": "Anomalous external IP; invalid MFA challenge attempt 1",
            },
            {
                "event_id": "AUTH-003",
                "timestamp": "2026-11-20T09:19:05Z",
                "user_id": "EMP-FIN-104",
                "email": "rohan.deshmukh@asterionfin.example",
                "source_ip": "203.0.113.95",
                "session_id": "NONE",
                "application": "pay.asterionfin.example",
                "event_type": "login",
                "status": "FAILED",
                "notes": "Anomalous external IP; invalid MFA challenge attempt 2",
            },
            {
                "event_id": "AUTH-004",
                "timestamp": "2026-11-20T09:20:15Z",
                "user_id": "EMP-FIN-104",
                "email": "rohan.deshmukh@asterionfin.example",
                "source_ip": "203.0.113.95",
                "session_id": "NONE",
                "application": "pay.asterionfin.example",
                "event_type": "login",
                "status": "FAILED",
                "notes": "Anomalous external IP; legacy fallback bypass attempt",
            },
            {
                "event_id": "AUTH-005",
                "timestamp": "2026-11-20T09:22:30Z",
                "user_id": "EMP-FIN-104",
                "email": "rohan.deshmukh@asterionfin.example",
                "source_ip": "203.0.113.95",
                "session_id": "SES-9941-HYDRA",
                "application": "pay.asterionfin.example",
                "event_type": "login",
                "status": "SUCCESS",
                "notes": "Unauthorized session established from external IP 203.0.113.95",
            },
            {
                "event_id": "AUTH-006",
                "timestamp": "2026-11-20T09:41:00Z",
                "user_id": "EMP-FIN-104",
                "email": "rohan.deshmukh@asterionfin.example",
                "source_ip": "203.0.113.95",
                "session_id": "SES-9941-HYDRA",
                "application": "pay.asterionfin.example",
                "event_type": "payment_instruction_modified",
                "status": "SUCCESS",
                "notes": "Beneficiary altered and PAY-REQ-7721 approved during anomalous session",
            },
            {
                "event_id": "AUTH-007",
                "timestamp": "2026-11-20T10:15:00Z",
                "user_id": "EMP-FIN-108",
                "email": "meera.nair@asterionfin.example",
                "source_ip": "192.0.2.50",
                "session_id": "SES-4488-CORP",
                "application": "soc.asterionfin.example",
                "event_type": "incident_reported",
                "status": "SUCCESS",
                "notes": "Finance Controller reports unauthorized PAY-REQ-7721 disbursement",
            },
            {
                "event_id": "AUTH-008",
                "timestamp": "2026-11-20T10:20:00Z",
                "user_id": "EMP-SOC-001",
                "email": "vikram.kulkarni@asterionfin.example",
                "source_ip": "192.0.2.15",
                "session_id": "SES-SOC-100",
                "application": "pay.asterionfin.example",
                "event_type": "session_revoked",
                "status": "SUCCESS",
                "notes": "SOC revoked SES-9941-HYDRA and isolated WKS-FIN-104",
            },
        ],
    )


def _generate_financial_evidence(evidence_dir: Path) -> None:
    """Create synthetic banking, UPI/IMPS/NEFT, and fictional crypto wallet logs."""
    fin_dir = evidence_dir / "financial"

    _write_csv(
        fin_dir / "transactions.csv",
        [
            "transaction_id",
            "timestamp",
            "source",
            "destination",
            "amount",
            "currency",
            "method",
            "utr_reference",
            "status",
            "incident_id",
            "risk_indicators",
        ],
        [
            {
                "transaction_id": "TXN-001",
                "timestamp": "2026-11-20T09:45:12Z",
                "source": "ASTERION_CORP_01",
                "destination": "MULE_ACC_01",
                "amount": "450000.00",
                "currency": "INR",
                "method": "UPI",
                "utr_reference": "UTR202611200001",
                "status": "SUCCESS",
                "incident_id": "INC-2026-HYDRA-01",
                "risk_indicators": "new_beneficiary;unusual_amount;linked_to_SES-9941-HYDRA",
            },
            {
                "transaction_id": "TXN-002",
                "timestamp": "2026-11-20T09:49:30Z",
                "source": "MULE_ACC_01",
                "destination": "MULE_ACC_02",
                "amount": "270000.00",
                "currency": "INR",
                "method": "IMPS",
                "utr_reference": "UTR202611200002",
                "status": "SUCCESS",
                "incident_id": "INC-2026-HYDRA-01",
                "risk_indicators": "rapid_transfer;account_splitting",
            },
            {
                "transaction_id": "TXN-003",
                "timestamp": "2026-11-20T09:52:05Z",
                "source": "MULE_ACC_01",
                "destination": "MULE_ACC_03",
                "amount": "175000.00",
                "currency": "INR",
                "method": "UPI",
                "utr_reference": "UTR202611200003",
                "status": "SUCCESS",
                "incident_id": "INC-2026-HYDRA-01",
                "risk_indicators": "rapid_transfer;account_splitting",
            },
            {
                "transaction_id": "TXN-004",
                "timestamp": "2026-11-20T10:03:40Z",
                "source": "MULE_ACC_02",
                "destination": "CRYPTO_EXCH_SIM_01",
                "amount": "250000.00",
                "currency": "INR",
                "method": "IMPS",
                "utr_reference": "UTR202611200004",
                "status": "SUCCESS",
                "incident_id": "INC-2026-HYDRA-01",
                "risk_indicators": "fiat_to_crypto_onramp_sim;high_velocity",
            },
            {
                "transaction_id": "TXN-005",
                "timestamp": "2026-11-20T10:11:15Z",
                "source": "MULE_ACC_03",
                "destination": "MULE_ACC_04",
                "amount": "100000.00",
                "currency": "INR",
                "method": "NEFT",
                "utr_reference": "UTR202611200005",
                "status": "FROZEN",
                "incident_id": "INC-2026-HYDRA-01",
                "risk_indicators": "bank_fraud_hold_applied;rapid_layering",
            },
        ],
    )

    _write_csv(
        fin_dir / "account-ledger.csv",
        [
            "account_id",
            "account_type",
            "institution",
            "opening_balance_inr",
            "closing_balance_inr",
            "frozen_recoverable_inr",
            "account_status",
            "notes",
        ],
        [
            {
                "account_id": "ASTERION_CORP_01",
                "account_type": "corporate_victim",
                "institution": "Simulated Corporate Bank India",
                "opening_balance_inr": "1250000.00",
                "closing_balance_inr": "800000.00",
                "frozen_recoverable_inr": "0.00",
                "account_status": "ACTIVE_PROTECTED",
                "notes": "Legitimate victim corporate settlement account",
            },
            {
                "account_id": "MULE_ACC_01",
                "account_type": "suspected_mule_tier1",
                "institution": "Simulated Metro Cooperative Bank",
                "opening_balance_inr": "0.00",
                "closing_balance_inr": "5000.00",
                "frozen_recoverable_inr": "5000.00",
                "account_status": "FROZEN_BY_BANK",
                "notes": "Received INR 450,000; split INR 445,000 within 7 minutes",
            },
            {
                "account_id": "MULE_ACC_02",
                "account_type": "suspected_mule_tier2",
                "institution": "Simulated Deccan Digital Bank",
                "opening_balance_inr": "0.00",
                "closing_balance_inr": "20000.00",
                "frozen_recoverable_inr": "20000.00",
                "account_status": "FROZEN_BY_BANK",
                "notes": "Received INR 270,000; sent INR 250,000 to CRYPTO_EXCH_SIM_01",
            },
            {
                "account_id": "MULE_ACC_03",
                "account_type": "suspected_mule_tier2",
                "institution": "Simulated Western FinTech Payments",
                "opening_balance_inr": "0.00",
                "closing_balance_inr": "75000.00",
                "frozen_recoverable_inr": "75000.00",
                "account_status": "FROZEN_BY_BANK",
                "notes": "Received INR 175,000; INR 100,000 NEFT frozen in transit",
            },
            {
                "account_id": "MULE_ACC_04",
                "account_type": "suspected_mule_tier3",
                "institution": "Simulated Coastal Commercial Bank",
                "opening_balance_inr": "0.00",
                "closing_balance_inr": "0.00",
                "frozen_recoverable_inr": "100000.00",
                "account_status": "HOLD_IN_TRANSIT",
                "notes": "TXN-005 INR 100,000 placed on regulatory hold prior to settlement",
            },
            {
                "account_id": "CRYPTO_EXCH_SIM_01",
                "account_type": "simulated_exchange_onramp",
                "institution": "Simulated Virtual Asset Desk",
                "opening_balance_inr": "0.00",
                "closing_balance_inr": "250000.00",
                "frozen_recoverable_inr": "0.00",
                "account_status": "CONVERTED_UNRECOVERED",
                "notes": "Converted INR 250,000 into fictional SIM-USDT tokens",
            },
        ],
    )

    _write_csv(
        fin_dir / "wallet-transfers.csv",
        [
            "transfer_id",
            "timestamp",
            "source_wallet",
            "destination_wallet",
            "token_symbol",
            "token_amount",
            "fiat_equivalent_inr",
            "tx_hash_sim",
            "classification",
            "notes",
        ],
        [
            {
                "transfer_id": "WLT-SIM-001",
                "timestamp": "2026-11-20T10:06:10Z",
                "source_wallet": "HYDRA-SIM-EXCH-ONRAMP-0001",
                "destination_wallet": "HYDRA-SIM-WALLET-ALPHA-0000",
                "token_symbol": "SIM-USDT",
                "token_amount": "2850.00",
                "fiat_equivalent_inr": "250000.00",
                "tx_hash_sim": "0xSIMULATED_HASH_HYDRA_0001_INVALID",
                "classification": "synthetic",
                "notes": "Simulated conversion from TXN-004 fiat deposit",
            },
            {
                "transfer_id": "WLT-SIM-002",
                "timestamp": "2026-11-20T10:09:45Z",
                "source_wallet": "HYDRA-SIM-WALLET-ALPHA-0000",
                "destination_wallet": "HYDRA-SIM-WALLET-EXIT-9999",
                "token_symbol": "SIM-USDT",
                "token_amount": "2850.00",
                "fiat_equivalent_inr": "250000.00",
                "tx_hash_sim": "0xSIMULATED_HASH_HYDRA_0002_INVALID",
                "classification": "synthetic",
                "notes": "Simulated hop to unattributed external wallet identifier",
            },
        ],
    )


def generate_all_evidence(evidence_dir: Path, force: bool = False) -> Path:
    """Generate the complete Operation Hydra synthetic evidence dataset."""
    manifest_path = evidence_dir / "manifest.json"
    if manifest_path.exists() and not force:
        raise FileExistsError(
            f"{manifest_path} already exists. Refusing to overwrite original evidence "
            "without --force."
        )

    _generate_emails_and_headers(evidence_dir)
    _generate_network_evidence(evidence_dir)
    _generate_endpoint_evidence(evidence_dir)
    _generate_authentication_evidence(evidence_dir)
    _generate_financial_evidence(evidence_dir)

    manifest = build_manifest(evidence_dir, acquired_at=DEFAULT_ACQUIRED_AT)
    write_manifest(manifest, manifest_path)

    custody = build_chain_of_custody(manifest, acquired_at=DEFAULT_ACQUIRED_AT)
    write_manifest(custody, evidence_dir / "chain-of-custody.json")
    return manifest_path


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Generate deterministic synthetic forensic evidence for Operation Hydra."
    )
    parser.add_argument(
        "--evidence-dir",
        type=Path,
        default=ROOT_DIR / "evidence",
        help="Destination evidence directory (default: evidence/).",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="Explicitly allow regenerating existing synthetic evidence.",
    )
    args = parser.parse_args()

    try:
        manifest_path = generate_all_evidence(args.evidence_dir, force=args.force)
    except FileExistsError as exc:
        print(f"[ERROR] {exc}", file=sys.stderr)
        return 1

    print(f"[OK] Generated synthetic evidence and sealed manifest at {manifest_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
