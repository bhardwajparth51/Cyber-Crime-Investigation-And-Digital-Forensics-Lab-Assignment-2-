"""RFC 5322 email parsing and metadata extraction for phishing forensics."""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from email import policy
from email.message import EmailMessage
from email.parser import BytesParser
from email.utils import getaddresses, parsedate_to_datetime
from pathlib import Path
from typing import Any

URL_RE = re.compile(r"https?://[^\s<>\"'\)\]]+", re.IGNORECASE)
IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
RECEIVED_FROM_RE = re.compile(
    r"from\s+([^\s(]+)(?:\s*\(([^)]+)\))?\s+by\s+([^\s;]+)",
    re.IGNORECASE,
)


@dataclass(frozen=True)
class ReceivedHop:
    """Single SMTP relay hop parsed from a Received header."""

    hop_index: int
    raw_header: str
    from_host: str | None
    from_ip: str | None
    by_host: str | None
    timestamp_utc: str | None


@dataclass(frozen=True)
class AttachmentInfo:
    """Forensic metadata for an email attachment (no payload execution)."""

    filename: str
    content_type: str
    size_bytes: int
    sha256: str


@dataclass(frozen=True)
class ParsedEmail:
    """Structured representation of an email artifact."""

    sample_id: str
    filename: str
    from_raw: str
    from_address: str
    from_domain: str
    reply_to_raw: str | None
    reply_to_address: str | None
    reply_to_domain: str | None
    return_path_raw: str | None
    return_path_address: str | None
    return_path_domain: str | None
    to_addresses: list[str]
    subject: str
    date_raw: str | None
    date_utc: str | None
    message_id: str | None
    authentication_results_raw: str | None
    received_chain: list[ReceivedHop] = field(default_factory=list)
    urls: list[str] = field(default_factory=list)
    attachments: list[AttachmentInfo] = field(default_factory=list)


def extract_address_and_domain(header_value: str | None) -> tuple[str | None, str | None]:
    """Return (lowercase_email, lowercase_domain) from an address header."""
    if not header_value:
        return None, None
    parsed = getaddresses([header_value])
    for _, addr in parsed:
        cleaned = addr.strip().lower()
        if "@" in cleaned:
            return cleaned, cleaned.split("@", 1)[1]
    return None, None


def parse_rfc2822_timestamp_utc(value: str | None) -> str | None:
    """Normalize an RFC 2822 date string to UTC ISO-8601 format."""
    if not value:
        return None
    try:
        dt = parsedate_to_datetime(value.strip())
    except (TypeError, ValueError):
        return None
    if dt.tzinfo is None:
        return dt.strftime("%Y-%m-%dT%H:%M:%SZ")
    return _format_utc(dt)


def _format_utc(dt: Any) -> str:
    """Format an aware datetime into canonical UTC ISO-8601."""
    from datetime import timezone

    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def parse_received_headers(headers: list[str]) -> list[ReceivedHop]:
    """Parse Received headers in chronological transit order (origin first)."""
    hops: list[ReceivedHop] = []
    # Received headers are prepended by MTAs, so reverse gives earliest hop first.
    for idx, raw in enumerate(reversed(headers), start=1):
        match = RECEIVED_FROM_RE.search(raw)
        from_host = match.group(1) if match else None
        from_paren = match.group(2) if match else None
        by_host = match.group(3) if match else None

        ip_match = IPV4_RE.search(from_paren or "") or IPV4_RE.search(raw)
        from_ip = ip_match.group(0) if ip_match else None

        timestamp_utc = None
        if ";" in raw:
            timestamp_utc = parse_rfc2822_timestamp_utc(raw.rsplit(";", 1)[1])

        hops.append(
            ReceivedHop(
                hop_index=idx,
                raw_header=raw.strip(),
                from_host=from_host,
                from_ip=from_ip,
                by_host=by_host,
                timestamp_utc=timestamp_utc,
            )
        )
    return hops


def _extract_urls_and_attachments(msg: EmailMessage) -> tuple[list[str], list[AttachmentInfo]]:
    """Extract URLs from text parts and metadata from non-inline attachments."""
    urls: list[str] = []
    seen_urls: set[str] = set()
    attachments: list[AttachmentInfo] = []

    for part in msg.walk():
        if part.is_multipart():
            continue
        disposition = part.get_content_disposition()
        filename = part.get_filename()
        content_type = part.get_content_type()

        if disposition == "attachment" or filename:
            payload = part.get_payload(decode=True) or b""
            attachments.append(
                AttachmentInfo(
                    filename=filename or "unnamed_attachment",
                    content_type=content_type,
                    size_bytes=len(payload),
                    sha256=hashlib.sha256(payload).hexdigest(),
                )
            )
            if content_type in {"text/plain", "text/html"}:
                text = payload.decode(part.get_content_charset() or "utf-8", errors="replace")
                for url in URL_RE.findall(text):
                    cleaned = url.rstrip(".,;)")
                    if cleaned not in seen_urls:
                        seen_urls.add(cleaned)
                        urls.append(cleaned)
            continue

        if content_type in {"text/plain", "text/html"}:
            payload = part.get_payload(decode=True) or b""
            text = payload.decode(part.get_content_charset() or "utf-8", errors="replace")
            for url in URL_RE.findall(text):
                cleaned = url.rstrip(".,;)")
                if cleaned not in seen_urls:
                    seen_urls.add(cleaned)
                    urls.append(cleaned)

    return urls, attachments


def parse_eml_bytes(raw_bytes: bytes, sample_id: str, filename: str = "<memory>") -> ParsedEmail:
    """Parse raw RFC 5322 email bytes into a structured ParsedEmail object."""
    msg = BytesParser(policy=policy.default).parsebytes(raw_bytes)

    from_raw = str(msg.get("From", "")).strip()
    from_addr, from_dom = extract_address_and_domain(from_raw)

    reply_to_raw = str(msg["Reply-To"]).strip() if msg.get("Reply-To") else None
    reply_addr, reply_dom = extract_address_and_domain(reply_to_raw)

    return_path_raw = str(msg["Return-Path"]).strip() if msg.get("Return-Path") else None
    rp_addr, rp_dom = extract_address_and_domain(return_path_raw)

    to_list = [addr.strip().lower() for _, addr in getaddresses(msg.get_all("To", [])) if addr]
    date_raw = str(msg["Date"]).strip() if msg.get("Date") else None
    date_utc = parse_rfc2822_timestamp_utc(date_raw)

    received_raw = [str(h) for h in msg.get_all("Received", [])]
    received_chain = parse_received_headers(received_raw)
    urls, attachments = _extract_urls_and_attachments(msg)

    return ParsedEmail(
        sample_id=sample_id,
        filename=filename,
        from_raw=from_raw,
        from_address=from_addr or "",
        from_domain=from_dom or "",
        reply_to_raw=reply_to_raw,
        reply_to_address=reply_addr,
        reply_to_domain=reply_dom,
        return_path_raw=return_path_raw,
        return_path_address=rp_addr,
        return_path_domain=rp_dom,
        to_addresses=to_list,
        subject=str(msg.get("Subject", "")).strip(),
        date_raw=date_raw,
        date_utc=date_utc,
        message_id=str(msg["Message-ID"]).strip() if msg.get("Message-ID") else None,
        authentication_results_raw=(
            str(msg["Authentication-Results"]).strip()
            if msg.get("Authentication-Results")
            else None
        ),
        received_chain=received_chain,
        urls=urls,
        attachments=attachments,
    )


def parse_eml_file(file_path: Path, sample_id: str | None = None) -> ParsedEmail:
    """Read and parse an .eml file from disk."""
    inferred_id = sample_id or file_path.stem.upper().replace("PHISHING-", "PHISH-")
    return parse_eml_bytes(file_path.read_bytes(), sample_id=inferred_id, filename=file_path.name)
