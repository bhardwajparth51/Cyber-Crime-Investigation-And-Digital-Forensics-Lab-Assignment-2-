"""DNS record analysis using synthetic evidence offline or opt-in live lookups."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any


def load_synthetic_dns(dns_json_path: Path) -> dict[str, Any]:
    """Load synthetic DNS and WHOIS records from evidence/network/dns-records.json."""
    return json.loads(dns_json_path.read_text(encoding="utf-8"))


def analyze_synthetic_dns(dns_json_path: Path, protected_domain: str = "asterionfin.example") -> list[dict[str, Any]]:
    """Inspect synthetic DNS records for SPF, DKIM, DMARC, and attacker lookalike gaps."""
    data = load_synthetic_dns(dns_json_path)
    domains = data.get("domains", {})
    findings: list[dict[str, Any]] = []

    for domain, record in sorted(domains.items()):
        dmarc = record.get("dmarc")
        dkim_selectors = record.get("dkim_selectors", {})
        spf = record.get("spf")
        role = record.get("role", "unknown")

        observations: list[str] = []
        if domain == protected_domain:
            observations.append("Protected corporate domain enforces strict DMARC (p=reject) and hard-fail SPF (-all).")
        else:
            observations.append(f"Synthetic adversarial domain classified as '{role}'.")
            if not dmarc:
                observations.append("No DMARC policy published, consistent with disposable phishing infrastructure.")
            if not dkim_selectors:
                observations.append("No DKIM selector published.")
            if spf and "~all" in spf:
                observations.append("Permissive SPF softfail (~all) configured.")

        findings.append(
            {
                "domain": domain,
                "role": role,
                "a_records": record.get("a", []),
                "aaaa_records": record.get("aaaa", []),
                "mx_records": record.get("mx", []),
                "txt_records": record.get("txt", []),
                "spf_record": spf,
                "dkim_selectors": list(dkim_selectors.keys()),
                "dmarc_record": dmarc,
                "verification_scope": "synthetic_offline_dataset",
                "observations": observations,
            }
        )
    return findings


def live_dns_lookup(
    domain: str,
    record_type: str = "A",
    analyst_approved: bool = False,
) -> list[str]:
    """Perform a live DNS query only when explicit analyst approval is granted."""
    if not analyst_approved:
        raise PermissionError(
            "External DNS lookup blocked: analyst_approved=True is required before querying live services."
        )

    import dns.resolver

    answers = dns.resolver.resolve(domain, record_type)
    return [str(rdata) for rdata in answers]
