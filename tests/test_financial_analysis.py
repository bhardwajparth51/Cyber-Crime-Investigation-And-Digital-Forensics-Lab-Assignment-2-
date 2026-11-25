"""Focused unit tests for financial validation, fund-flow tracing, and mule indicators."""

from __future__ import annotations

from pathlib import Path

import pandas as pd

from src.financial_analysis.fund_tracer import (
    build_transaction_graph,
    detect_account_splitting,
    detect_rapid_transfers,
    trace_fund_paths,
)
from src.financial_analysis.mule_account_detector import identify_suspected_mule_accounts
from src.financial_analysis.transaction_analyzer import (
    calculate_financial_impact,
    validate_transactions,
)

ROOT_DIR = Path(__file__).resolve().parent.parent
FIN_DIR = ROOT_DIR / "evidence" / "financial"


def test_financial_flow_and_impact_reconciliation() -> None:
    txn_df, report = validate_transactions(FIN_DIR / "transactions.csv")
    assert report.is_valid is True

    wallet_df = pd.read_csv(FIN_DIR / "wallet-transfers.csv")
    graph = build_transaction_graph(txn_df, wallet_df)
    paths = trace_fund_paths(graph)
    assert len(paths) == 2
    assert any("HYDRA-SIM-WALLET-EXIT-9999" in path for path in paths)
    assert any("MULE_ACC_04" in path for path in paths)

    splitting = detect_account_splitting(txn_df)
    assert len(splitting) == 1
    assert splitting[0]["source_account"] == "MULE_ACC_01"
    assert splitting[0]["distinct_destinations"] == ["MULE_ACC_02", "MULE_ACC_03"]

    rapid = detect_rapid_transfers(txn_df, threshold_seconds=900)
    assert len(rapid) >= 2

    mules = identify_suspected_mule_accounts(txn_df)
    high_conf = {m["account_id"] for m in mules if m["classification"] == "high_confidence_simulated_mule"}
    assert {"MULE_ACC_01", "MULE_ACC_02"}.issubset(high_conf)

    impact = calculate_financial_impact(
        FIN_DIR / "transactions.csv",
        FIN_DIR / "account-ledger.csv",
        FIN_DIR / "wallet-transfers.csv",
    )
    assert impact["total_fraudulent_outflow_inr"] == 450000.0
    assert impact["frozen_recoverable_inr"] == 200000.0
    assert impact["unrecovered_loss_inr"] == 250000.0


def test_transaction_validation_catches_duplicates_invalid_amounts_and_missing_timestamps(
    tmp_path: Path,
) -> None:
    bad_csv = tmp_path / "bad_transactions.csv"
    bad_csv.write_text(
        "\n".join(
            [
                "transaction_id,timestamp,source,destination,amount,currency,method,status",
                "TXN-100,2026-11-20T10:00:00Z,ACC_A,ACC_B,1000,INR,UPI,SUCCESS",
                "TXN-100,2026-11-20T10:01:00Z,ACC_A,ACC_C,500,INR,UPI,SUCCESS",
                "TXN-101,,ACC_B,ACC_D,-250,INR,IMPS,SUCCESS",
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    _, report = validate_transactions(bad_csv)
    assert report.is_valid is False
    assert "TXN-100" in report.duplicate_transaction_ids
    assert "TXN-101" in report.invalid_amount_rows
    assert "TXN-101" in report.invalid_timestamp_rows
