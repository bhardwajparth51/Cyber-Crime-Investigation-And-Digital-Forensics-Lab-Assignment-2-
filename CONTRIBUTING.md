# Contributing Guidelines

This repository is an academic digital forensics investigation for **Operation Hydra**. Contributions must uphold strict forensic safety and reproducibility standards:

1. **No Live Malware or Offensive Payloads:** Never commit functional malware, shellcode, exploit scripts, credential harvesters, or network scanners.
2. **Synthetic Data Only:** Use reserved domains (`.example`, `.invalid`), reserved documentation IPs (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`), and explicitly fictional accounts/wallets.
3. **Evidence Immutability:** Never silently modify files under `evidence/`. If synthetic evidence is intentionally regenerated via `scripts/generate_evidence.py`, re-generate and verify the manifest with `scripts/verify_evidence.py`.
4. **Offline Reproducibility:** All analysis scripts and `pytest` tests must execute cleanly offline without external API keys or internet access.
5. **Code Quality:** Follow Python 3.11+ typing conventions, keep functions concise and readable, and run `pytest` before submitting changes.
