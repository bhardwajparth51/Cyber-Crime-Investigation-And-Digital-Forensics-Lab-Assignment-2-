# Forensic Tool Selection and Justification

All core investigation modules in Operation Hydra run **100% offline** against deterministic synthetic evidence. External reputation and registry services are documented strictly as **optional investigation aids** for live incidents and must never be invoked automatically or supplied with private attachments, credentials, or personal data.

## Core Analysis Tools (Offline-Capable)

| Tool | Purpose | Investigation Stage | Internet Required? |
|---|---|---|---|
| **Python 3.11+** | Core automation, pipeline orchestration, and correlation | All stages | No |
| **`email.parser` (stdlib)** | RFC 5322 email header, MIME, URL, and attachment metadata parsing | Stage 2 (Phishing) | No |
| **`dnspython`** | Optional live A/AAAA/MX/TXT/SPF/DKIM/DMARC queries (gated by `analyst_approved=True`) | Stage 1–2 (Infrastructure) | Only in live mode |
| **`python-whois`** | Optional live domain registration age and registrar lookup (gated by `analyst_approved=True`) | Stage 1–2 (Infrastructure) | Only in live mode |
| **`hashlib` (stdlib)** | SHA-256 cryptographic hashing for evidence manifest and attachments | Evidence Preservation | No |
| **`NetworkX`** | Directed transaction graph modeling, path tracing, and split detection | Stage 5 (Financial Fraud) | No |
| **`pandas`** | Structured CSV validation, ledger reconciliation, and summary aggregation | Stage 4–5 (Logs & Finance) | No |
| **`pytest`** | Automated verification of forensic logic and edge cases | Quality Assurance | No |

## Detailed Tool Profiles

### 1. Python 3.11+ & `email.parser`
- **Investigation Stage:** Phishing and header forensics.
- **Installation:** Built into Python standard library (`python3 --version` >= 3.11).
- **Example Command:**
  ```bash
  python -c "from pathlib import Path; from src.email_analysis.header_parser import parse_eml_file; print(parse_eml_file(Path('evidence/emails/phishing-01.eml')).from_address)"
  ```
- **Expected Output:** `billing@asteri0nfin.example`
- **Limitations:** Parses embedded `Authentication-Results` text as reported by the simulated gateway; cannot cryptographically verify DKIM signatures without live DNS public keys.
- **Internet Access:** Not required.

### 2. `hashlib` (SHA-256)
- **Investigation Stage:** Evidence acquisition, attachment profiling, and integrity verification.
- **Installation:** Python standard library.
- **Example Command:**
  ```bash
  python scripts/verify_evidence.py
  ```
- **Expected Output:** `[VERIFIED] All evidence artifacts match their recorded SHA-256 hashes.`
- **Limitations:** Detects post-acquisition modification but cannot prove provenance prior to initial acquisition without trusted timestamps.
- **Internet Access:** Not required.

### 3. `dnspython` (plus `dig` / `nslookup` CLI equivalents)
- **Investigation Stage:** Infrastructure and email authentication reconnaissance.
- **Installation:** `pip install dnspython` (or OS `dnsutils` package for `dig`/`nslookup`).
- **Example Commands:**
  ```bash
  # Offline synthetic inspection
  python -c "from pathlib import Path; from src.infrastructure.dns_lookup import analyze_synthetic_dns; print(len(analyze_synthetic_dns(Path('evidence/network/dns-records.json'))))"

  # Live investigation CLI equivalent (requires explicit analyst approval on real domains)
  dig +short TXT _dmarc.asterionfin.example
  nslookup -type=MX asterionfin.example
  ```
- **Expected Output:** Offline returns `4` domain profiles; live DNS queries return current TXT/MX resource records when resolving real infrastructure.
- **Limitations:** Current DNS records may change after an attack (fast-flux or registrar suspension), so historical passive DNS may be needed in real cases.
- **Internet Access:** Offline mode: No. Live `dig`/`nslookup`/`dnspython`: Yes (analyst approval required).

### 4. `python-whois` (plus `whois` CLI)
- **Investigation Stage:** Lookalike domain age profiling.
- **Installation:** `pip install python-whois` (or OS `whois` client).
- **Example Command:**
  ```bash
  python -c "from pathlib import Path; from src.infrastructure.whois_lookup import analyze_synthetic_whois; print([d['domain'] for d in analyze_synthetic_whois(Path('evidence/network/dns-records.json')) if d['newly_registered_flag']])"
  ```
- **Expected Output:** `['asteri0nfin.example', 'asterion-billing.invalid', 'asterionfin-verify.example']`
- **Limitations:** GDPR privacy redaction frequently masks registrant identity in live WHOIS/RDAP responses.
- **Internet Access:** Offline mode: No. Live mode: Yes (analyst approval required).

### 5. `NetworkX` & `pandas`
- **Investigation Stage:** Financial fraud tracing, rapid transfer detection, and mule clustering.
- **Installation:** `pip install networkx pandas`
- **Example Command:**
  ```bash
  python scripts/analyze_campaign.py
  ```
- **Expected Output:** Reconstructed paths from `ASTERION_CORP_01` through `MULE_ACC_01` to `MULE_ACC_04` and `HYDRA-SIM-WALLET-EXIT-9999`, plus `INR 450,000.00` outflow reconciliation.
- **Limitations:** Graph analysis reflects recorded ledger edges; cash withdrawals or off-platform OTC swaps create blind spots outside banking logs.
- **Internet Access:** Not required.

### 6. `pytest`
- **Investigation Stage:** Reproducible verification of parsers, validators, timeline ordering, and hash checks.
- **Installation:** `pip install pytest`
- **Example Command:**
  ```bash
  pytest -v
  ```
- **Expected Output:** All unit tests passing offline with deterministic synthetic fixtures.
- **Limitations:** Verifies code correctness against synthetic cases rather than real-world telemetry noise.
- **Internet Access:** Not required.

## Optional External Investigation Aids (Live Incidents Only)

> **Operational Policy:** Never upload private email attachments, `.eml` files, credentials, or PII to public third-party portals. Only query public IOCs (hashes, public IPs, domains) after explicit analyst approval.

| Tool | Purpose | Example Usage | Limitations | Internet Required? |
|---|---|---|---|---|
| **VirusTotal** | File hash, URL, and domain reputation lookup | Query public SHA-256 hash or domain via web/API (hash-only, never upload sensitive attachments) | Public submissions expose files to third parties; absence of hits does not prove safety | Yes |
| **AbuseIPDB** | Crowdsourced IP abuse confidence and ASN context | Check suspicious relay/login IP (`203.0.113.95` in a real incident) | Reflects community reports; shared VPN/NAT IPs can cause false positives | Yes |
| **MXToolbox** | Web-based SPF, DKIM, DMARC, and blacklist diagnostics | Inspect public domain MX/DMARC syntax during triage | Point-in-time external view; does not verify internal mail gateway logs | Yes |
| **ICANN Lookup** | Authoritative RDAP domain registration and registrar abuse contact lookup | Query suspicious lookalike domain registration timestamps and abuse email | Registrant PII typically redacted; requires registrar/legal process for subscriber data | Yes |
