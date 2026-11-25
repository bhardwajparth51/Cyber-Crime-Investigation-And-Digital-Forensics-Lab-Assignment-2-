"""Phishing, spoofing, domain lookalike detection, and explainable risk classification."""

from __future__ import annotations

from dataclasses import asdict
from difflib import SequenceMatcher
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from src.email_analysis.authentication_checks import interpret_authentication
from src.email_analysis.header_parser import ParsedEmail, parse_eml_file

LEGITIMATE_DOMAIN = "asterionfin.example"
HOMOGLYPH_TABLE = str.maketrans({"0": "o", "1": "l", "3": "e", "5": "s", "@": "a"})


def normalize_lookalike(domain: str) -> str:
    """Normalize common visual substitutions (e.g., 0->o, 1->l) for comparison."""
    base = domain.lower().split(".", 1)[0]
    return base.translate(HOMOGLYPH_TABLE).replace("-", "")


def assess_domain_similarity(
    candidate_domain: str | None,
    reference_domain: str = LEGITIMATE_DOMAIN,
) -> dict[str, Any]:
    """Compare a domain against the protected corporate domain for lookalike traits."""
    if not candidate_domain:
        return {"domain": None, "is_exact_match": False, "is_lookalike": False, "reason": "missing_domain"}

    cand = candidate_domain.lower().strip()
    ref = reference_domain.lower().strip()
    if cand == ref or cand.endswith(f".{ref}"):
        return {"domain": cand, "is_exact_match": True, "is_lookalike": False, "similarity": 1.0}

    labels = [lbl for lbl in cand.split(".") if lbl]
    stem_labels = labels[:-1] if len(labels) > 1 else labels
    ref_label = ref.split(".", 1)[0]
    norm_ref = normalize_lookalike(ref)

    best_raw_ratio = 0.0
    best_norm_ratio = 0.0
    matched_homoglyph = False
    matched_brand = False

    for cand_label in stem_labels:
        raw_ratio = SequenceMatcher(None, cand_label, ref_label).ratio()
        norm_cand = normalize_lookalike(cand_label)
        norm_ratio = SequenceMatcher(None, norm_cand, norm_ref).ratio()
        best_raw_ratio = max(best_raw_ratio, raw_ratio)
        best_norm_ratio = max(best_norm_ratio, norm_ratio)
        if norm_cand == norm_ref and cand != ref:
            matched_homoglyph = True
        if ref_label in norm_cand or norm_cand == norm_ref:
            matched_brand = True

    is_lookalike = matched_homoglyph or matched_brand or best_norm_ratio >= 0.78 or best_raw_ratio >= 0.78

    reason = None
    if matched_homoglyph:
        reason = f"homoglyph/TLD lookalike of '{ref}'"
    elif matched_brand:
        reason = f"brand-impersonating domain containing '{ref_label}'"
    elif is_lookalike:
        reason = f"high lexical similarity ({best_raw_ratio:.2f}) to '{ref}'"

    return {
        "domain": cand,
        "is_exact_match": False,
        "is_lookalike": is_lookalike,
        "similarity": round(max(best_raw_ratio, best_norm_ratio), 3),
        "reason": reason,
    }


def _find_suspicious_urls(urls: list[str], reference_domain: str = LEGITIMATE_DOMAIN) -> list[dict[str, Any]]:
    """Flag URLs pointing to lookalike or non-corporate domains."""
    flagged: list[dict[str, Any]] = []
    for url in urls:
        host = (urlparse(url).hostname or "").lower()
        sim = assess_domain_similarity(host, reference_domain)
        if not sim["is_exact_match"]:
            flagged.append(
                {
                    "url": url,
                    "host": host,
                    "lookalike": sim["is_lookalike"],
                    "reason": sim.get("reason") or f"external destination '{host}' outside '{reference_domain}'",
                }
            )
    return flagged


def analyze_parsed_email(
    parsed: ParsedEmail,
    legitimate_domain: str = LEGITIMATE_DOMAIN,
) -> dict[str, Any]:
    """Analyze a ParsedEmail and produce an explainable forensic finding dictionary."""
    auth = interpret_authentication(parsed, legitimate_org_domain=legitimate_domain)
    findings: list[str] = []
    severity_points = 0

    reply_to_mismatch = bool(
        parsed.reply_to_address and parsed.from_address and parsed.reply_to_address != parsed.from_address
    )
    if reply_to_mismatch:
        severity_points += 2
        findings.append(
            f"Reply-To address ({parsed.reply_to_address}) differs from From address ({parsed.from_address})."
        )

    return_path_mismatch = bool(
        parsed.return_path_domain and parsed.from_domain and parsed.return_path_domain != parsed.from_domain
    )
    if return_path_mismatch:
        severity_points += 1
        findings.append(
            f"Return-Path domain ({parsed.return_path_domain}) does not align with From domain ({parsed.from_domain})."
        )

    sender_sim = assess_domain_similarity(parsed.from_domain, legitimate_domain)
    if sender_sim["is_lookalike"]:
        severity_points += 3
        findings.append(f"Sender domain '{parsed.from_domain}' is a {sender_sim['reason']}.")
    elif sender_sim["is_exact_match"] and auth.dmarc == "simulated_fail":
        severity_points += 3
        findings.append(
            f"Email claims corporate sender '{parsed.from_address}' but failed simulated SPF/DKIM/DMARC checks (direct domain spoofing)."
        )

    if parsed.reply_to_domain and parsed.reply_to_domain != legitimate_domain:
        reply_sim = assess_domain_similarity(parsed.reply_to_domain, legitimate_domain)
        if reply_sim["is_lookalike"]:
            severity_points += 1
            findings.append(f"Reply-To domain '{parsed.reply_to_domain}' is a {reply_sim['reason']}.")

    if auth.spf in {"simulated_fail", "simulated_softfail"}:
        severity_points += 2
        findings.append(f"Simulated SPF check returned {auth.spf} (not verified against live DNS).")
    if auth.dkim in {"simulated_fail", "simulated_none"}:
        severity_points += 1
        findings.append(f"Simulated DKIM check returned {auth.dkim}.")
    if auth.dmarc == "simulated_fail":
        severity_points += 2
        findings.append("Simulated DMARC alignment failed.")
    elif auth.dmarc == "simulated_none" and sender_sim["is_lookalike"]:
        severity_points += 1
        findings.append(
            "Sender lookalike domain has no DMARC policy and self-signed SPF/DKIM to evade basic perimeter checks."
        )

    suspicious_urls = _find_suspicious_urls(parsed.urls, legitimate_domain)
    if suspicious_urls:
        severity_points += 2
        for item in suspicious_urls:
            findings.append(f"Suspicious URL '{item['url']}' ({item['reason']}).")

    attachments = [asdict(att) for att in parsed.attachments]
    for att in parsed.attachments:
        lowered = att.filename.lower()
        if lowered.endswith((".html", ".htm", ".zip", ".exe", ".js")) or ".pdf." in lowered:
            severity_points += 2
            findings.append(
                f"High-risk attachment pattern detected: '{att.filename}' ({att.content_type}, SHA-256 {att.sha256[:12]}...)."
            )

    if severity_points >= 6:
        risk_level = "high"
    elif severity_points >= 3:
        risk_level = "medium"
    else:
        risk_level = "low"

    return {
        "sample_id": parsed.sample_id,
        "filename": parsed.filename,
        "timestamp_utc": parsed.date_utc,
        "sender": parsed.from_address,
        "recipient": parsed.to_addresses,
        "subject": parsed.subject,
        "reply_to": parsed.reply_to_address,
        "return_path": parsed.return_path_address,
        "reply_to_mismatch": reply_to_mismatch,
        "return_path_mismatch": return_path_mismatch,
        "spf": auth.spf,
        "dkim": auth.dkim,
        "dmarc": auth.dmarc,
        "authentication_scope": auth.verification_scope,
        "live_dns_verified": auth.live_dns_verified,
        "received_hops": [asdict(hop) for hop in parsed.received_chain],
        "suspicious_urls": suspicious_urls,
        "attachments": attachments,
        "risk_level": risk_level,
        "findings": findings,
    }


def analyze_email_directory(emails_dir: Path) -> list[dict[str, Any]]:
    """Parse and analyze all .eml files in a directory sorted by filename."""
    results: list[dict[str, Any]] = []
    for eml_path in sorted(emails_dir.glob("*.eml")):
        parsed = parse_eml_file(eml_path)
        results.append(analyze_parsed_email(parsed))
    return results
