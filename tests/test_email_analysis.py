"""Focused unit tests for email header parsing, authentication interpretation, and phishing detection."""

from __future__ import annotations

from pathlib import Path

from src.email_analysis.authentication_checks import interpret_authentication
from src.email_analysis.header_parser import parse_eml_bytes, parse_eml_file
from src.email_analysis.phishing_analyzer import analyze_parsed_email, assess_domain_similarity

ROOT_DIR = Path(__file__).resolve().parent.parent
EMAILS_DIR = ROOT_DIR / "evidence" / "emails"


def test_phish_01_header_mismatch_and_simulated_auth() -> None:
    parsed = parse_eml_file(EMAILS_DIR / "phishing-01.eml", sample_id="PHISH-01")
    result = analyze_parsed_email(parsed)

    assert result["sample_id"] == "PHISH-01"
    assert result["sender"] == "billing@asteri0nfin.example"
    assert result["reply_to_mismatch"] is True
    assert result["spf"] == "simulated_fail"
    assert result["dkim"] == "simulated_none"
    assert result["dmarc"] == "simulated_fail"
    assert result["live_dns_verified"] is False
    assert result["risk_level"] == "high"
    assert len(result["attachments"]) == 1
    assert result["attachments"][0]["filename"] == "Vendor_Invoice_INV-2026-8841.pdf.html"


def test_phish_03_self_signed_lookalike_distinction() -> None:
    parsed = parse_eml_file(EMAILS_DIR / "phishing-03.eml", sample_id="PHISH-03")
    auth = interpret_authentication(parsed)

    assert auth.spf == "simulated_pass"
    assert auth.dkim == "simulated_pass"
    assert auth.dmarc == "simulated_none"
    assert auth.dmarc_aligned_inferred is False
    assert auth.live_dns_verified is False

    similarity = assess_domain_similarity("asteri0nfin.example")
    assert similarity["is_lookalike"] is True
    assert similarity["is_exact_match"] is False


def test_missing_optional_email_headers_handled_gracefully() -> None:
    raw = (
        b"From: sender@asterionfin.example\r\n"
        b"To: analyst@asterionfin.example\r\n"
        b"Subject: Minimal Synthetic Message\r\n"
        b"\r\n"
        b"Plain body without Reply-To, Return-Path, Date, or Authentication-Results.\r\n"
    )
    parsed = parse_eml_bytes(raw, sample_id="PHISH-MIN")
    result = analyze_parsed_email(parsed)

    assert parsed.reply_to_address is None
    assert parsed.return_path_address is None
    assert parsed.date_utc is None
    assert result["reply_to_mismatch"] is False
    assert result["spf"] == "missing_header"
    assert result["dkim"] == "missing_header"
    assert result["dmarc"] == "missing_header"
