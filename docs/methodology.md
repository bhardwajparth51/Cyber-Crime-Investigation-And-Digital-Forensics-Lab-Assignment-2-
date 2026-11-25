# Investigation Methodology

Operation Hydra follows a structured, repeatable forensic workflow designed to preserve original artifacts while deriving explainable findings across five telemetry domains.

## 1. Evidence Acquisition and Integrity Sealing

- All synthetic artifacts under `evidence/` are treated as read-only original evidence.
- Prior to analysis, `scripts/verify_evidence.py` validates every file against [manifest.json](../evidence/manifest.json) using streaming SHA-256 digests (`src/common/hashing.py`).
- All derived JSON outputs and visual figures are written exclusively to `reports/generated/`, `reports/ioc-report.json`, and `reports/figures/` so original evidence is never modified.

## 2. Email Header and Authentication Forensics

- `src/email_analysis/header_parser.py` parses raw `.eml` files with Python's standard `email.parser` (`policy.default`), extracting addressing headers, chronological `Received` hops, embedded `Authentication-Results`, URLs, and attachment SHA-256 hashes.
- `src/email_analysis/authentication_checks.py` interprets SPF, DKIM, and DMARC fields strictly as `simulated_*` values and marks `live_dns_verified = False` so synthetic header strings are never misrepresented as live DNS cryptographic verification.
- `src/email_analysis/phishing_analyzer.py` evaluates `Reply-To` / `Return-Path` mismatches, homoglyph and brand-similarity domain spoofing, suspicious attachment extensions, and external URLs to emit explainable risk findings.

## 3. Offline Infrastructure Investigation

- `src/infrastructure/` resolves DNS records (`A`, `AAAA`, `MX`, `TXT`, `SPF`, `DKIM`, `DMARC`), WHOIS domain registration age, and IP classifications (`RFC 5737 TEST-NET`) from synthetic offline evidence (`dns-records.json`, `ip-observations.csv`, `connection-logs.json`).
- Live DNS/WHOIS helpers require an explicit `analyst_approved=True` guard to prevent accidental external network queries or evidence leakage during offline runs.

## 4. Safe Malware Telemetry and IOC Extraction

- `samples/malware/harmless-simulator/simulator.py` models a Trojan invoice decoy via static synthetic JSON events without executing binaries, opening sockets, or collecting real credentials.
- `src/malware_analysis/payload_decoder.py` decodes a benign Base64 JSON text fixture (`encoded_payload_fixture.txt`) strictly as data.
- `src/malware_analysis/behavior_analyzer.py` classifies the telemetry as a simulated Trojan and explicitly rules out RAT, keylogger, logic bomb, and worm classifications based on absent behavioral indicators.
- `src/malware_analysis/ioc_extractor.py` consolidates deduplicated IOCs with provenance, earliest timestamp, confidence, and `origin: "synthetic"`.

## 5. Financial Flow Reconstruction and Mule Detection

- `src/financial_analysis/transaction_analyzer.py` validates transaction integrity (detecting missing timestamps, duplicate IDs, non-positive amounts, and self-transfers) and reconciles corporate loss vs. frozen mule balances.
- `src/financial_analysis/fund_tracer.py` constructs a directed `NetworkX` graph linking fiat transfers (`UPI`, `IMPS`, `NEFT`) to simulated wallet hops, detecting rapid forwarding (`<= 15 min`) and multi-destination splitting.
- `src/financial_analysis/mule_account_detector.py` scores intermediary accounts on pass-through ratio, velocity, and fan-out splitting while noting that behavioral indicators alone do not prove individual criminal liability.

## 6. Cross-Source Timeline Correlation

- `src/correlation/timeline_builder.py` normalizes all multi-source timestamps to UTC (`YYYY-MM-DDTHH:MM:SSZ`), isolates any records with missing/unparseable timestamps into `unsequenced_events`, and computes key incident milestones.
- `src/correlation/evidence_correlator.py` maps every high-level investigative conclusion to specific supporting artifacts and evidentiary caveats.
