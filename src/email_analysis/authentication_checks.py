"""Interpretation of embedded SPF, DKIM, and DMARC header results.

Explicitly distinguishes synthetic header claims embedded in simulated .eml
evidence from live cryptographic/DNS verification against external mail servers.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from src.email_analysis.header_parser import ParsedEmail

SPF_RE = re.compile(r"\bspf=([a-z]+)", re.IGNORECASE)
DKIM_RE = re.compile(r"\bdkim=([a-z]+)", re.IGNORECASE)
DMARC_RE = re.compile(r"\bdmarc=([a-z]+)", re.IGNORECASE)
SMTP_MAILFROM_RE = re.compile(r"\bsmtp\.mailfrom=([^\s;]+)", re.IGNORECASE)
DKIM_DOMAIN_RE = re.compile(r"\bheader\.d=([^\s;]+)", re.IGNORECASE)
HEADER_FROM_RE = re.compile(r"\bheader\.from=([^\s;]+)", re.IGNORECASE)


@dataclass(frozen=True)
class AuthInterpretation:
    """Structured SPF, DKIM, and DMARC interpretation for an email sample."""

    spf: str
    dkim: str
    dmarc: str
    spf_domain: str | None
    dkim_domain: str | None
    header_from_domain: str | None
    dmarc_aligned_inferred: bool
    live_dns_verified: bool
    verification_scope: str
    notes: list[str]


def _normalize_simulated_status(match: re.Match[str] | None, header_present: bool) -> str:
    """Prefix embedded header values with 'simulated_' to prevent false certainty."""
    if not header_present:
        return "missing_header"
    if not match:
        return "simulated_none"
    return f"simulated_{match.group(1).lower()}"


def _extract_domain(token: str | None) -> str | None:
    if not token:
        return None
    cleaned = token.strip().strip("<>").lower()
    return cleaned.split("@", 1)[1] if "@" in cleaned else cleaned


def interpret_authentication(
    parsed: ParsedEmail,
    legitimate_org_domain: str = "asterionfin.example",
) -> AuthInterpretation:
    """Interpret Authentication-Results headers without claiming live DNS proof."""
    raw = parsed.authentication_results_raw or ""
    header_present = bool(raw.strip())

    spf = _normalize_simulated_status(SPF_RE.search(raw), header_present)
    dkim = _normalize_simulated_status(DKIM_RE.search(raw), header_present)
    dmarc = _normalize_simulated_status(DMARC_RE.search(raw), header_present)

    spf_match = SMTP_MAILFROM_RE.search(raw)
    dkim_match = DKIM_DOMAIN_RE.search(raw)
    hfrom_match = HEADER_FROM_RE.search(raw)

    spf_domain = _extract_domain(spf_match.group(1)) if spf_match else parsed.return_path_domain
    dkim_domain = _extract_domain(dkim_match.group(1)) if dkim_match else None
    header_from_domain = (
        _extract_domain(hfrom_match.group(1)) if hfrom_match else (parsed.from_domain or None)
    )

    spf_aligned = bool(
        spf == "simulated_pass" and spf_domain and header_from_domain and spf_domain == header_from_domain
    )
    dkim_aligned = bool(
        dkim == "simulated_pass" and dkim_domain and header_from_domain and dkim_domain == header_from_domain
    )
    dmarc_aligned_inferred = (spf_aligned or dkim_aligned) and (dmarc == "simulated_pass")

    notes: list[str] = []
    if not header_present:
        notes.append("Authentication-Results header is absent; sender authenticity cannot be inferred.")
    else:
        notes.append(
            "Values represent embedded synthetic Authentication-Results headers, not live DNS/DKIM checks."
        )

    if spf in {"simulated_fail", "simulated_softfail"}:
        notes.append(f"SPF reported {spf} for envelope domain '{spf_domain or 'unknown'}'.")
    if dkim in {"simulated_fail", "simulated_none"}:
        notes.append(f"DKIM reported {dkim}; message integrity and sender signing are unverified.")
    if dmarc == "simulated_fail":
        notes.append("DMARC reported simulated_fail due to failed alignment or authentication.")
    elif dmarc == "simulated_none" and header_from_domain and header_from_domain != legitimate_org_domain:
        notes.append(
            f"Sender domain '{header_from_domain}' passed its own SPF/DKIM but lacks a DMARC policy "
            f"and does not match organizational domain '{legitimate_org_domain}'."
        )

    return AuthInterpretation(
        spf=spf,
        dkim=dkim,
        dmarc=dmarc,
        spf_domain=spf_domain,
        dkim_domain=dkim_domain,
        header_from_domain=header_from_domain,
        dmarc_aligned_inferred=dmarc_aligned_inferred,
        live_dns_verified=False,
        verification_scope="synthetic_header_only",
        notes=notes,
    )
