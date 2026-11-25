"""Explainable mule account detection from transaction velocity and splitting patterns."""

from __future__ import annotations

from typing import Any

import pandas as pd

from src.financial_analysis.fund_tracer import detect_account_splitting, detect_rapid_transfers


def identify_suspected_mule_accounts(
    transactions_df: pd.DataFrame,
    victim_account: str = "ASTERION_CORP_01",
) -> list[dict[str, Any]]:
    """Score non-victim accounts using pass-through velocity, splitting, and risk flags."""
    rapid_list = detect_rapid_transfers(transactions_df)
    split_map = {item["source_account"]: item for item in detect_account_splitting(transactions_df)}

    rapid_by_account: dict[str, list[dict[str, Any]]] = {}
    for item in rapid_list:
        rapid_by_account.setdefault(item["account"], []).append(item)

    accounts = sorted(
        set(transactions_df["source"]).union(set(transactions_df["destination"])) - {victim_account}
    )
    reports: list[dict[str, Any]] = []

    for acc in accounts:
        inbound = transactions_df.loc[transactions_df["destination"] == acc]
        outbound = transactions_df.loc[transactions_df["source"] == acc]

        inflow = float(inbound["amount_numeric"].sum())
        outflow = float(outbound["amount_numeric"].sum())
        pass_through = round(outflow / inflow, 3) if inflow > 0 else 0.0

        indicators: list[str] = []
        score = 0

        if inflow > 0 and pass_through >= 0.80:
            score += 2
            indicators.append(f"High pass-through ratio ({pass_through:.0%} of inbound funds forwarded).")

        if acc in rapid_by_account:
            min_delay = min(e["elapsed_seconds"] for e in rapid_by_account[acc])
            score += 2
            indicators.append(f"Rapid onward transfer within {min_delay} seconds of receipt.")

        if acc in split_map:
            targets = split_map[acc]["distinct_destinations"]
            score += 2
            indicators.append(f"Account splitting across {len(targets)} destinations ({', '.join(targets)}).")

        if any("onramp" in str(r) or "CRYPTO" in str(d) for r, d in zip(outbound["risk_indicators"], outbound["destination"])):
            score += 2
            indicators.append("Direct routing into simulated fiat-to-crypto exchange on-ramp.")

        if any(s == "FROZEN" for s in inbound["status"]):
            score += 1
            indicators.append("Inbound transfer placed on bank fraud hold (FROZEN).")

        if score >= 4:
            classification = "high_confidence_simulated_mule"
        elif score >= 2:
            classification = "suspected_mule_or_intermediary"
        else:
            classification = "downstream_endpoint"

        reports.append(
            {
                "account_id": acc,
                "inbound_inr": round(inflow, 2),
                "outbound_inr": round(outflow, 2),
                "pass_through_ratio": pass_through,
                "classification": classification,
                "indicators": indicators,
                "attribution_note": "Account-level behavioral indicator only; does not establish real-person identity.",
            }
        )

    return reports
