"""WHOIS registration inspection for synthetic offline and opt-in live domains."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def analyze_synthetic_whois(
    dns_json_path: Path,
    incident_date_utc: str = "2026-11-20T00:00:00Z",
) -> list[dict[str, Any]]:
    """Evaluate domain age and registration anomalies from synthetic WHOIS metadata."""
    data = json.loads(dns_json_path.read_text(encoding="utf-8"))
    incident_dt = datetime.fromisoformat(incident_date_utc.replace("Z", "+00:00"))
    results: list[dict[str, Any]] = []

    for domain, record in sorted(data.get("domains", {}).items()):
        whois_info = record.get("whois", {})
        created_raw = whois_info.get("created_at")
        age_days: int | None = None
        newly_registered = False
        if created_raw:
            created_dt = datetime.fromisoformat(created_raw.replace("Z", "+00:00")).astimezone(timezone.utc)
            age_days = (incident_dt - created_dt).days
            newly_registered = age_days <= 30

        results.append(
            {
                "domain": domain,
                "registrar": whois_info.get("registrar"),
                "created_at": created_raw,
                "registrant_org": whois_info.get("registrant_org"),
                "country": whois_info.get("country"),
                "age_days_at_incident": age_days,
                "newly_registered_flag": newly_registered,
                "verification_scope": "synthetic_offline_dataset",
            }
        )
    return results


def live_whois_lookup(domain: str, analyst_approved: bool = False) -> dict[str, Any]:
    """Perform a live WHOIS lookup only with explicit analyst approval."""
    if not analyst_approved:
        raise PermissionError(
            "External WHOIS lookup blocked: analyst_approved=True is required before querying live registries."
        )

    import whois

    result = whois.whois(domain)
    return dict(result)
