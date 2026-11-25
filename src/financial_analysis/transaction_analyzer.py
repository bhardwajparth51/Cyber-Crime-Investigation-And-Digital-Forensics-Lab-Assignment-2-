"""Transaction validation and financial loss/recovery calculation."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import pandas as pd

VALID_STATUSES = {"SUCCESS", "FROZEN", "FAILED", "PENDING"}


@dataclass(frozen=True)
class ValidationReport:
    """Validation status for synthetic banking transaction records."""

    is_valid: bool
    total_rows: int
    duplicate_transaction_ids: list[str]
    duplicate_utr_references: list[str]
    invalid_amount_rows: list[str]
    invalid_timestamp_rows: list[str]
    invalid_status_rows: list[str]


def _parse_utc(ts: str) -> datetime | None:
    if not ts or not isinstance(ts, str):
        return None
    try:
        dt = datetime.fromisoformat(ts.strip().replace("Z", "+00:00"))
        return dt.astimezone(timezone.utc)
    except ValueError:
        return None


def validate_transactions(transactions_csv: Path) -> tuple[pd.DataFrame, ValidationReport]:
    """Load and validate financial transactions for duplicates, amounts, and timestamps."""
    df = pd.read_csv(transactions_csv, dtype=str).fillna("")

    seen_ids: set[str] = set()
    seen_utrs: set[str] = set()
    dup_ids: list[str] = []
    dup_utrs: list[str] = []
    bad_amounts: list[str] = []
    bad_timestamps: list[str] = []
    bad_statuses: list[str] = []
    parsed_amounts: list[float] = []

    for idx, row in df.iterrows():
        txn_id = row.get("transaction_id", "").strip() or f"ROW-{idx}"
        utr = row.get("utr_reference", "").strip()

        if txn_id in seen_ids:
            dup_ids.append(txn_id)
        seen_ids.add(txn_id)

        if utr:
            if utr in seen_utrs:
                dup_utrs.append(utr)
            seen_utrs.add(utr)

        try:
            amt = float(row.get("amount", ""))
            if amt <= 0:
                bad_amounts.append(txn_id)
            parsed_amounts.append(amt)
        except ValueError:
            bad_amounts.append(txn_id)
            parsed_amounts.append(0.0)

        if _parse_utc(row.get("timestamp", "")) is None:
            bad_timestamps.append(txn_id)

        status = row.get("status", "").strip().upper()
        if status not in VALID_STATUSES:
            bad_statuses.append(txn_id)

    df["amount_numeric"] = parsed_amounts
    report = ValidationReport(
        is_valid=not (dup_ids or dup_utrs or bad_amounts or bad_timestamps or bad_statuses),
        total_rows=len(df),
        duplicate_transaction_ids=dup_ids,
        duplicate_utr_references=dup_utrs,
        invalid_amount_rows=bad_amounts,
        invalid_timestamp_rows=bad_timestamps,
        invalid_status_rows=bad_statuses,
    )
    return df, report


def calculate_financial_impact(
    transactions_csv: Path,
    ledger_csv: Path,
    wallet_csv: Path,
    victim_account: str = "ASTERION_CORP_01",
) -> dict[str, Any]:
    """Compute direct loss, recoverable frozen funds, and unrecovered crypto simulation outflow."""
    txn_df, validation = validate_transactions(transactions_csv)
    if not validation.is_valid:
        raise ValueError(f"Transaction validation failed: {validation}")

    ledger_df = pd.read_csv(ledger_csv)
    wallet_df = pd.read_csv(wallet_csv)

    victim_outflow = float(
        txn_df.loc[
            (txn_df["source"] == victim_account) & (txn_df["status"] == "SUCCESS"),
            "amount_numeric",
        ].sum()
    )
    frozen_recoverable = float(ledger_df["frozen_recoverable_inr"].sum())
    crypto_converted = float(
        ledger_df.loc[
            ledger_df["account_status"] == "CONVERTED_UNRECOVERED",
            "closing_balance_inr",
        ].sum()
    )
    unrecovered = round(victim_outflow - frozen_recoverable, 2)
    recovery_pct = round((frozen_recoverable / victim_outflow) * 100, 2) if victim_outflow else 0.0

    wallet_hops = wallet_df.to_dict(orient="records")
    return {
        "incident_id": "INC-2026-HYDRA-01",
        "currency": "INR",
        "victim_account": victim_account,
        "total_fraudulent_outflow_inr": round(victim_outflow, 2),
        "frozen_recoverable_inr": round(frozen_recoverable, 2),
        "unrecovered_loss_inr": unrecovered,
        "simulated_crypto_converted_inr": round(crypto_converted, 2),
        "recovery_rate_percent": recovery_pct,
        "transaction_count": int(len(txn_df)),
        "method_breakdown": txn_df.groupby("method")["amount_numeric"].sum().to_dict(),
        "simulated_wallet_hops": wallet_hops,
        "verification_scope": "synthetic_financial_simulation",
    }
