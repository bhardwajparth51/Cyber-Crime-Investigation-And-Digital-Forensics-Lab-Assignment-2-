"""IP address classification and synthetic reputation correlation."""

from __future__ import annotations

import csv
import ipaddress
import json
from pathlib import Path
from typing import Any

TEST_NET_RANGES = [
    ("RFC5737-TEST-NET-1", ipaddress.ip_network("192.0.2.0/24")),
    ("RFC5737-TEST-NET-2", ipaddress.ip_network("198.51.100.0/24")),
    ("RFC5737-TEST-NET-3", ipaddress.ip_network("203.0.113.0/24")),
]


def classify_ip_range(ip_str: str) -> str:
    """Return the documentation/private/public classification of an IPv4/IPv6 address."""
    ip_obj = ipaddress.ip_address(ip_str)
    for label, network in TEST_NET_RANGES:
        if ip_obj in network:
            return label
    if ip_obj.is_private:
        return "RFC1918-PRIVATE"
    if ip_obj.is_reserved or ip_obj.is_loopback:
        return "RESERVED"
    return "PUBLIC_ROUTABLE"


def analyze_ip_observations(
    ip_csv_path: Path,
    connection_logs_path: Path,
) -> dict[str, Any]:
    """Correlate synthetic IP observations with recorded network connections."""
    observations: list[dict[str, Any]] = []
    with ip_csv_path.open("r", encoding="utf-8", newline="") as handle:
        for row in csv.DictReader(handle):
            ip_addr = row["ip_address"]
            observations.append(
                {
                    "ip_address": ip_addr,
                    "computed_range": classify_ip_range(ip_addr),
                    "role": row["role"],
                    "simulated_reputation": row["simulated_reputation"],
                    "confidence": row["confidence"],
                    "first_seen": row["first_seen"],
                    "notes": row["notes"],
                    "verification_scope": "synthetic_offline_dataset",
                }
            )

    connections = json.loads(connection_logs_path.read_text(encoding="utf-8"))
    suspicious_ips = {
        obs["ip_address"]
        for obs in observations
        if "suspicious" in obs["simulated_reputation"] or "malicious" in obs["simulated_reputation"]
    }
    suspicious_connections = [
        conn
        for conn in connections
        if conn.get("src_ip") in suspicious_ips or conn.get("dst_ip") in suspicious_ips
    ]

    return {
        "total_observed_ips": len(observations),
        "suspicious_ip_count": len(suspicious_ips),
        "ip_observations": observations,
        "suspicious_connections": suspicious_connections,
    }
