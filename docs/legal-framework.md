# Legal Framework Mapping (Indian and International Law)

> **Academic Disclaimer:** This legal analysis maps a fictional November 2026 simulation (`Operation Hydra`) to statutory provisions for educational cybercrime classification. It does not constitute legal advice and does not assert the guilt of any real or identifiable person.

## 1. Transition from IPC to Bharatiya Nyaya Sanhita, 2023 (BNS)

The **Bharatiya Nyaya Sanhita, 2023 (BNS)** replaced the Indian Penal Code, 1860 (IPC) effective **1 July 2024**. Because the fictional Operation Hydra incident occurs in **November 2026**, substantive criminal provisions are mapped to the **BNS, 2023** alongside the **Information Technology Act, 2000 (IT Act)**, with historical IPC equivalents noted only for academic reference.

## 2. Cybercrime Category Decomposition and Statutory Assessment

### Category 1: Phishing

- **Activity & Stage:** Sending deceptive invoice and mandate-verification lures (`PHISH-01`, `PHISH-02`, `PHISH-03`) to induce finance staff to open malicious attachments or visit a fake payment portal (Stage 2).
- **Supporting Evidence:** `phishing-01.eml`, `phishing-02.eml`, `phishing-03.eml`, `email-01..03-headers.txt`.
- **Victim & Assets:** Employees `EMP-FIN-104`, `EMP-FIN-108`; corporate mail gateway and payment portal trust.
- **Indian Provisions:** **IT Act § 66D** (cheating by personation using computer resource); **BNS § 318** (cheating, historical IPC § 415/420) and **BNS § 319** (cheating by personation, historical IPC § 416/419).
- **International Equivalents:** **Budapest Convention Art. 8** (computer-related fraud, where deceptive input induces property loss); **18 U.S.C. § 1030(a)(4)** (CFAA, if targeting a US-jurisdiction protected computer with intent to defraud).
- **Remedies & Challenges:** Criminal prosecution, domain takedown, and civil damages; attribution is complicated by redacted WHOIS records and cross-border relays.

### Category 2: Email and Website Spoofing

- **Activity & Stage:** Forging the corporate `From` header (`finance-ops@asterionfin.example` in `PHISH-02`) and operating lookalike domains (`asteri0nfin.example`, `asterionfin-verify.example`) hosting a spoofed verification portal (Stages 1–2).
- **Supporting Evidence:** `phishing-01..03.eml`, `dns-records.json`, `connection-logs.json`.
- **Victim & Assets:** Asterion Financial Services brand integrity, domain reputation, and employee authentication perimeter.
- **Indian Provisions:** **IT Act § 66D** (cheating by personation via computer resource); **BNS § 336** (forgery, expressly covering *false electronic records*, historical IPC § 463/464/465) and **BNS § 340** (using a forged electronic record as genuine, historical IPC § 471).
- **International Equivalents:** **Budapest Convention Art. 7** (computer-related forgery — inputting/altering computer data resulting in inauthentic data intended to be acted upon as authentic).
- **Remedies & Challenges:** Registrar abuse escalation, UDRP/INDRP domain disputes, and DMARC enforcement; lookalike domains that self-sign SPF/DKIM (`PHISH-03`) evade naive perimeter checks.

### Category 3: Identity Theft / Digital Impersonation

- **Activity & Stage:** Impersonating corporate billing/audit desks in email lures and subsequently misusing `EMP-FIN-104`'s credentials/session identifier (`SES-9941-HYDRA`) to authorize `PAY-REQ-7721` (Stages 2–4).
- **Supporting Evidence:** `phishing-02.eml`, `login-events.csv` (`AUTH-005`, `AUTH-006`).
- **Victim & Assets:** Employee digital identity (`EMP-FIN-104`), corporate approval authority.
- **Indian Provisions:** **IT Act § 66C** (fraudulently or dishonestly using the password, electronic signature, or unique identification feature of another person); **IT Act § 66D**; **BNS § 319**.
- **International Equivalents:** **18 U.S.C. § 1030(a)(6)** (trafficking in passwords/access info if applicable) and **18 U.S.C. § 1030(a)(2)** (obtaining information via unauthorized access).
- **Remedies & Challenges:** Session revocation, credential rotation, and criminal complaint under § 66C; distinguishing unauthorized external operator misuse from insider action requires correlating IP (`203.0.113.95`) and endpoint logs.

### Category 4: Unauthorized Access

- **Activity & Stage:** Repeated failed authentication probes (`AUTH-002`–`AUTH-004`) followed by unauthorized access to `pay.asterionfin.example` (`AUTH-005`) from anomalous external IP `203.0.113.95` and unauthorized modification of payment instructions (`AUTH-006`) (Stage 4).
- **Supporting Evidence:** `login-events.csv`, `ip-observations.csv`, `connection-logs.json` (`CONN-005`).
- **Victim & Assets:** Corporate payment approval platform (`pay.asterionfin.example`) and internal ledger data.
- **Indian Provisions:** **IT Act § 43(a)/(b)/(i)** (civil liability for unauthorized access, data copying, or tampering without owner permission) and **IT Act § 66** (criminal liability when § 43 acts are committed *dishonestly or fraudulently*); **IT Act § 70B(6)** & **CERT-In Directions (28 April 2022)** (mandatory 6-hour incident reporting and 180-day log retention).
- **International Equivalents:** **Budapest Convention Art. 2** (illegal access) and **Art. 4** (data interference); **18 U.S.C. § 1030(a)(2) & (a)(5)** (CFAA); **EU GDPR Art. 32–34** (only if EU residents' personal data is processed and compromised).
- **Remedies & Challenges:** Civil adjudication under § 43, criminal prosecution under § 66, and regulatory reporting to CERT-In; proving lack of authorization requires intact, time-synchronized logs (NIC/NPL NTP alignment per CERT-In 2022 Directions).

### Category 5: Malware Distribution (Simulated Trojan Decoy)

- **Activity & Stage:** Delivering a deceptive invoice attachment (`Vendor_Invoice_INV-2026-8841.pdf.html` / `Payment_Remittance_Batch_Nov20.zip`) whose simulated execution (`invoice_viewer.exe`) decodes staging configuration, targets a synthetic browser profile, and emits an outbound beacon (Stages 2–3).
- **Supporting Evidence:** `phishing-01.eml`, `phishing-02.eml`, `execution-events.json`, `malware-observations.json`, `encoded_payload_fixture.txt`.
- **Victim & Assets:** Corporate workstation `WKS-FIN-104` and endpoint integrity.
- **Indian Provisions:** **IT Act § 43(c)** (civil liability for introducing computer contaminant/virus) read with **IT Act § 66** (dishonest/fraudulent commission).
- **International Equivalents:** **Budapest Convention Art. 4 & 5** (data/system interference); **18 U.S.C. § 1030(a)(5)(A)** (knowingly causing transmission of a program/code causing damage).
- **Remedies & Challenges:** Host isolation, IOC blocking, and forensic imaging; telemetry alone without binary recovery must be classified cautiously (e.g., Trojan rather than assuming RAT/keylogger).

### Category 6: Financial Fraud and Payment Manipulation

- **Activity & Stage:** Modifying `PAY-REQ-7721`, initiating an unauthorized `INR 450,000` UPI transfer (`TXN-001`), splitting funds across mule accounts (`TXN-002`, `TXN-003`), and converting `INR 250,000` through a simulated crypto exchange (`TXN-004`, `WLT-SIM-001/002`) (Stage 5).
- **Supporting Evidence:** `transactions.csv`, `account-ledger.csv`, `wallet-transfers.csv`, `login-events.csv` (`AUTH-006`).
- **Victim & Assets:** Corporate account `ASTERION_CORP_01` (`INR 450,000` initial outflow; `INR 250,000` unrecovered).
- **Indian Provisions:** **BNS § 318(4)** (cheating and dishonestly inducing delivery of property, historical IPC § 420); **BNS § 61** (criminal conspiracy for coordinated mule layering, historical IPC § 120B); **IT Act § 66** & **§ 66D**.
- **International Equivalents:** **Budapest Convention Art. 8** (computer-related fraud causing loss of property via data alteration/input); **18 U.S.C. § 1030(a)(4)** (CFAA fraud).
- **Remedies & Challenges:** Immediate bank freeze/lien (which preserved `INR 200,000` in this scenario), NCRP/1930 escalation, and mutual legal assistance for virtual asset tracing; mule KYC verification and irreversible off-ramping remain major barriers.

### Category 7: Unsolicited / Bulk-Style Phishing Delivery (Spamming)

- **Activity & Stage:** Delivering unsolicited urgent financial action notices (`PHISH-03`, referencing urgent bulk-style mandate sign-off) via newly provisioned external infrastructure to induce portal interaction (Stage 2).
- **Supporting Evidence:** `phishing-03.eml`, `email-03-headers.txt`.
- **Victim & Assets:** Finance approver inbox (`meera.nair@asterionfin.example`) and enterprise mail filtering controls.
- **Indian Provisions:** India has no standalone anti-spam criminal statute equivalent to the US CAN-SPAM Act; however, **when coupled with deception or forged sender identity**, it is actionable under **IT Act § 66D** and **BNS § 318**, alongside TRAI/regulatory commercial communication rules where telecom channels are used. Note that **IT Act § 66A** (which previously penalized offensive messages) was struck down by the Supreme Court in *Shreya Singhal v. Union of India* (2015) and must **not** be cited as enforceable law.
- **International Equivalents:** **US CAN-SPAM Act (15 U.S.C. § 7701 et seq.)** (civil/criminal penalties for materially falsified header information in commercial email, US-specific); **EU ePrivacy Directive** (consent rules for electronic marketing, EU-specific).

## 3. Provisions Evaluated and Explicitly Excluded (Statutory Precision)

- **IT Act § 66E (Violation of Privacy):** Excluded. Section 66E applies specifically to capturing, publishing, or transmitting images of private bodily areas without consent; it does **not** apply to corporate financial or email phishing.
- **IT Act §§ 67, 67A, 67B (Obscene / Sexually Explicit Material / CSAM):** Excluded. None of the statutory elements are present in Operation Hydra.
- **IT Act § 66A:** Excluded. Declared unconstitutional in *Shreya Singhal v. Union of India* (2015).

## 4. Consolidated Legal Mapping Table

| Cybercrime | Evidence | Indian Provision | International Equivalent | Legal Considerations |
|---|---|---|---|---|
| **Phishing** | `phishing-01.eml`, `phishing-02.eml`, `phishing-03.eml` | IT Act § 66D; BNS § 318, § 319 *(IPC § 415/419/420)* | Budapest Convention Art. 8; CFAA 18 U.S.C. § 1030(a)(4) | Requires proof of deceptive inducement; synthetic headers do not replace live server logs. |
| **Email & Website Spoofing** | `phishing-01..03.eml`, `dns-records.json`, `connection-logs.json` | IT Act § 66D; BNS § 336, § 340 *(IPC § 463/465/471)* | Budapest Convention Art. 7 | Lookalike domains with self-signed SPF/DKIM bypass basic authentication checks; cross-border registrars complicate takedown. |
| **Identity Theft / Impersonation** | `phishing-02.eml`, `login-events.csv` (`AUTH-005`, `AUTH-006`) | IT Act § 66C, § 66D; BNS § 319 | CFAA 18 U.S.C. § 1030(a)(2), (a)(6) | Proving a specific individual used `SES-9941-HYDRA` requires ISP subscriber correlation beyond IP logs. |
| **Unauthorized Access** | `login-events.csv` (`AUTH-002..006`), `ip-observations.csv`, `CONN-005` | IT Act § 43 (civil) & § 66 (criminal); § 70B(6) / CERT-In 2022 Directions | Budapest Convention Art. 2 & 4; CFAA 18 U.S.C. § 1030(a)(2); GDPR Art. 32–34 | § 43 is civil compensation while § 66 requires dishonest/fraudulent intent; GDPR applies only if EU data subjects are affected; CFAA is US-only. |
| **Malware Distribution (Trojan Sim)** | `execution-events.json`, `malware-observations.json`, `encoded_payload_fixture.txt` | IT Act § 43(c) read with § 66 | Budapest Convention Art. 4 & 5; CFAA 18 U.S.C. § 1030(a)(5) | Telemetry supports Trojan classification; without captured binary/memory image, RAT/keylogger claims would be speculative. |
| **Financial Fraud & Layering** | `transactions.csv`, `account-ledger.csv`, `wallet-transfers.csv` | BNS § 318(4), § 61 *(IPC § 420, § 120B)*; IT Act § 66, § 66D | Budapest Convention Art. 8; CFAA 18 U.S.C. § 1030(a)(4) | Mule indicators support bank holds but not criminal conviction without KYC and beneficiary tracing; crypto wallet IDs do not prove real-world identity. |
| **Spamming (Unsolicited Spoofed Mail)** | `phishing-03.eml`, `email-03-headers.txt` | IT Act § 66D; BNS § 318 (when fraudulent; § 66A invalid) | US CAN-SPAM Act (falsified headers); EU ePrivacy Directive | India lacks a standalone anti-spam criminal offence; liability attaches to fraudulent deception/impersonation. |

## 5. Jurisdictional Limitations of International Frameworks

- **CFAA (18 U.S.C. § 1030):** Applies strictly under United States federal jurisdiction (typically requiring a protected computer used in or affecting US interstate/foreign commerce). It has no direct statutory force in India unless US infrastructure/victims create concurrent jurisdiction.
- **EU GDPR (Articles 32–34):** Regulates data protection, security of processing, and breach notification (72-hour supervisory notification under Art. 33) for EU/EEA controllers, processors, or targeting of EU residents—not general criminal prosecution of external cybercriminals.
- **Budapest Convention on Cybercrime (ETS No. 185):** Harmonizes substantive cybercrime offences and cross-border mutual legal assistance (MLA) / expedited preservation mechanisms among ratifying states, but domestic prosecution in India proceeds under Indian statutes (IT Act and BNS) and bilateral MLA treaties where applicable.
