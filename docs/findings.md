# Forensic Findings Summary

All findings below are derived deterministically from the synthetic Operation Hydra dataset by running `python scripts/analyze_campaign.py`.

## 1. Phishing and Spoofing Findings
- **PHISH-01 (`phishing-01.eml`):** Targeted `rohan.deshmukh@asterionfin.example` at `2026-11-20T08:42:10Z` from `billing@asteri0nfin.example` (homoglyph lookalike replacing `o` with `0`), with `Reply-To` mismatch (`settlement-desk@asterion-billing.invalid`), `simulated_fail` SPF/DMARC, `simulated_none` DKIM, suspicious portal link (`https://pay-verify.asterionfin-verify.example/invoice/8841`), and double-extension attachment `Vendor_Invoice_INV-2026-8841.pdf.html` (`191` bytes, SHA-256 `bf6c1fd6a8ee9840cae4bbf844d60a1228076b39f3caa7cf6a60364b22ab7f51`). Risk: **high**.
- **PHISH-02 (`phishing-02.eml`):** Targeted `rohan.deshmukh@asterionfin.example` at `2026-11-20T08:55:40Z` spoofing the corporate `From` address `finance-ops@asterionfin.example` via external relay `203.0.113.77`, with mismatched `Return-Path` (`bounce@asterion-billing.invalid`) and `Reply-To` (`ops-clearance@asterion-billing.invalid`), `simulated_softfail` SPF, `simulated_fail` DKIM/DMARC, and archive attachment `Payment_Remittance_Batch_Nov20.zip`. Risk: **high**.
- **PHISH-03 (`phishing-03.eml`):** Targeted Finance Controller `meera.nair@asterionfin.example` at `2026-11-20T09:04:15Z` from `audit-desk@asterionfin-verify.example`. The lookalike domain reported `simulated_pass` SPF/DKIM on its own infrastructure while publishing no DMARC policy (`simulated_none`), illustrating how lookalike domains bypass basic sender authentication checks. Risk: **high**.

## 2. Infrastructure Findings
- All three adversarial domains (`asteri0nfin.example`, `asterion-billing.invalid`, `asterionfin-verify.example`) were created `2` to `4` days prior to the 20 November 2026 attack (`newly_registered_flag: true`) with redacted registrant metadata.
- All observed IPs reside strictly inside RFC 5737 TEST-NET documentation ranges (`192.0.2.0/24` corporate, `198.51.100.0/24` and `203.0.113.0/24` external relays/login sources).

## 3. Malware Telemetry and IOC Findings
- **Classification:** **Simulated Trojan (Invoice Lure)** (`MAL-HYDRA-SIM-001`). Telemetry shows decoy attachment opening (`09:14:48Z`), suspicious `invoice_viewer.exe` execution (`09:15:02Z`), harmless Base64 config decoding (`09:15:09Z`), synthetic browser profile access attempt (`09:15:15Z`), and a single outbound beacon to `198.51.100.88` (`09:15:22Z`).
- **Negative Findings:** No persistent remote shell (RAT), no keystroke capture (keylogger), no dormant trigger (logic bomb), and no self-propagation (worm) were observed.
- **IOC Summary:** 23 unique synthetic IOCs extracted into [reports/ioc-report.json](../reports/ioc-report.json) (`5` domains, `4` IPs, `4` URLs, `4` SHA-256 digests, `3` filenames, `2` file paths, `1` process name).

## 4. Financial Fraud Findings
- **Initial Outflow:** `INR 450,000.00` (`TXN-001`, UPI) from `ASTERION_CORP_01` to `MULE_ACC_01` at `09:45:12Z` after `PAY-REQ-7721` was altered in session `SES-9941-HYDRA`.
- **Layering & Splitting:** `MULE_ACC_01` split `INR 445,000.00` (`98.9%` pass-through) within `413` seconds across `MULE_ACC_02` (`INR 270,000.00` IMPS) and `MULE_ACC_03` (`INR 175,000.00` UPI).
- **Recovery vs. Loss:** `INR 200,000.00` (`44.44%`) was frozen/held (`INR 5,000` in `MULE_ACC_01`, `INR 20,000` in `MULE_ACC_02`, `INR 75,000` in `MULE_ACC_03`, and `INR 100,000` held in transit on `TXN-005` -> `MULE_ACC_04`). `INR 250,000.00` (`55.56%`) was routed via `CRYPTO_EXCH_SIM_01` to fictional wallet `HYDRA-SIM-WALLET-EXIT-9999` and remains unrecovered.
