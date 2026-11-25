# Operation Hydra — Investigation Overview

## Case Summary

- **Investigator / Author:** Parth Bhardwaj (Roll No. `2301730289`)
- **Incident Identifier:** `INC-2026-HYDRA-01`
- **Campaign Designation:** Operation Hydra
- **Target Organization (Fictional):** Asterion Financial Services Pvt. Ltd. (`asterionfin.example`)
- **Primary Incident Date:** 20 November 2026 (UTC), preceded by lookalike domain setup beginning 16 November 2026
- **Classification:** Controlled Academic Digital Forensics Simulation (100% Synthetic Dataset)
- **GitHub Repository:** https://github.com/bhardwajparth51/Cyber-Crime-Investigation-And-Digital-Forensics-Lab-Assignment-2-

## Scenario Background

Operation Hydra simulates a coordinated multi-vector cybercrime campaign targeting finance and accounts personnel at Asterion Financial Services Pvt. Ltd. Rather than relying on a single exploit, the fictional threat group combines social engineering, lookalike domain infrastructure, email header spoofing, a Trojan-style decoy invoice payload, unauthorized access to a corporate payment portal, and rapid multi-tier financial layering across Indian payment rails (UPI, IMPS, NEFT) terminating in a simulated cryptocurrency conversion.

## Investigation Objectives

1. **Reconstruct the end-to-end attack chain** across reconnaissance, email delivery, endpoint telemetry, identity logs, and banking ledgers using normalized UTC timestamps.
2. **Analyze phishing and spoofing artifacts** (`phishing-01.eml` through `phishing-03.eml`), explicitly distinguishing embedded synthetic `Authentication-Results` headers from live DNS verification.
3. **Characterize simulated malware behavior** using a harmless event-driven telemetry simulator and extract deduplicated Indicators of Compromise (IOCs) into [reports/ioc-report.json](../reports/ioc-report.json).
4. **Trace fraudulent fund flows** using directed graph analysis (`NetworkX`) to quantify direct outflow, frozen/recoverable balances, and unrecovered losses.
5. **Map observed offences to Indian and international legal frameworks** (Information Technology Act, 2000; Bharatiya Nyaya Sanhita, 2023; CERT-In Directions, 2022; 18 U.S.C. § 1030; EU GDPR; Budapest Convention).
6. **Maintain strict forensic integrity** through SHA-256 hashing, chain-of-custody logging, and separation of original synthetic evidence from derived analysis outputs.

## Key Empirical Summary (From Offline Pipeline)

- **Emails Analyzed:** 3 synthetic `.eml` samples (`PHISH-01`, `PHISH-02`, `PHISH-03`), all classified `high` risk.
- **Malware Classification:** Simulated Trojan (Invoice Lure), distinct from RAT, keylogger, logic bomb, and worm behavior.
- **Extracted IOCs:** 23 unique synthetic IOCs across domains, IPs, URLs, filenames, file paths, process names, and SHA-256 hashes.
- **Financial Impact:** `INR 450,000.00` initial fraudulent outflow (`TXN-001`), `INR 200,000.00` frozen/recoverable across mule tiers (`44.44%`), and `INR 250,000.00` converted via simulated exchange on-ramp (`CRYPTO_EXCH_SIM_01` -> `HYDRA-SIM-WALLET-EXIT-9999`).
- **Sequenced Timeline:** 31 UTC-normalized events spanning `2026-11-16T04:12:00Z` to `2026-11-20T10:20:00Z`.
