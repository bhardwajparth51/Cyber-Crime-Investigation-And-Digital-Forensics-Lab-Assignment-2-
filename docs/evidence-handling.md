# Evidence Handling and Chain of Custody

## Core Principles

1. **Immutability of Original Evidence:** Files in `evidence/` are sealed at acquisition (`2026-11-20T10:30:00Z`) and must not be edited in place. `scripts/generate_evidence.py` refuses to overwrite an existing `manifest.json` unless `--force` is explicitly provided.
2. **Cryptographic Verification:** Every artifact is hashed using SHA-256 (`src/common/hashing.py`) and recorded in [manifest.json](../evidence/manifest.json).
3. **Separation of Original vs. Derived Data:** Derived analysis outputs are stored separately under `reports/generated/`, `reports/ioc-report.json`, and `reports/figures/`.
4. **Academic Simulation Notice:** Synthetic artifacts provide a controlled, reproducible academic model and are **not** court-admissible digital evidence of an actual crime (in contrast to real-world admissibility under Section 63 of the Bharatiya Sakshya Adhiniyam, 2023).

## Chain of Custody Summary

Recorded in [chain-of-custody.json](../evidence/chain-of-custody.json):

- **Sequence 1 (`2026-11-20T10:30:00Z`):** `Vikram Kulkarni (IR-Lead, Asterion SOC)` acquired and SHA-256 sealed 15 synthetic evidence files (`EV-001` through `EV-015`).
- **Sequence 2 (`2026-11-20T10:35:00Z`):** Operation Hydra forensic pipeline ingested `evidence/` read-only and routed derived outputs to `reports/generated/`.

## Preserved Evidence Inventory (`EV-001` – `EV-015`)

| ID | Relative Path | Source Provenance | Size (Bytes) | SHA-256 Digest (Prefix) |
|---|---|---|---:|---|
| `EV-001` | `authentication/login-events.csv` | `synthetic_identity_provider` | 1678 | `7e649faa4afc...` |
| `EV-002` | `emails/phishing-01.eml` | `synthetic_mail_gateway` | 2039 | `14b075adcfa1...` |
| `EV-003` | `emails/phishing-02.eml` | `synthetic_mail_gateway` | 1909 | `f56c35f14516...` |
| `EV-004` | `emails/phishing-03.eml` | `synthetic_mail_gateway` | 1485 | `d46c0c112112...` |
| `EV-005` | `endpoint/execution-events.json` | `synthetic_endpoint_simulator` | 1835 | `414ba3e27f1e...` |
| `EV-006` | `endpoint/malware-observations.json` | `synthetic_endpoint_simulator` | 1243 | `a89151654d81...` |
| `EV-007` | `financial/account-ledger.csv` | `synthetic_banking_ledger` | 1107 | `c72568280644...` |
| `EV-008` | `financial/transactions.csv` | `synthetic_banking_ledger` | 896 | `45cff5affdf4...` |
| `EV-009` | `financial/wallet-transfers.csv` | `synthetic_banking_ledger` | 560 | `26b1be4ab861...` |
| `EV-010` | `headers/email-01-headers.txt` | `synthetic_mail_gateway` | 1093 | `c3efdaa5e048...` |
| `EV-011` | `headers/email-02-headers.txt` | `synthetic_mail_gateway` | 1124 | `1b89690ca0c4...` |
| `EV-012` | `headers/email-03-headers.txt` | `synthetic_mail_gateway` | 1139 | `46ca0c1b906f...` |
| `EV-013` | `network/connection-logs.json` | `synthetic_network_sensor` | 1467 | `991de133ec6d...` |
| `EV-014` | `network/dns-records.json` | `synthetic_network_sensor` | 2969 | `ee7901c0d04b...` |
| `EV-015` | `network/ip-observations.csv` | `synthetic_network_sensor` | 1085 | `93751f2472af...` |

## Independent Verification

```bash
python scripts/verify_evidence.py
```
The verifier exits non-zero if any tracked file is modified, deleted, or untracked relative to `evidence/manifest.json`.
