"""Fund-flow graph reconstruction, rapid-transfer detection, and visualization."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
import networkx as nx
import pandas as pd


def _to_utc(ts: str) -> datetime:
    return datetime.fromisoformat(ts.strip().replace("Z", "+00:00")).astimezone(timezone.utc)


def build_transaction_graph(
    transactions_df: pd.DataFrame,
    wallet_df: pd.DataFrame | None = None,
) -> nx.DiGraph:
    """Build a directed graph of fiat transactions and optional simulated wallet hops."""
    graph = nx.DiGraph()

    for _, row in transactions_df.iterrows():
        src = str(row["source"]).strip()
        dst = str(row["destination"]).strip()
        amt = float(row["amount_numeric"])
        graph.add_node(src, layer="fiat")
        graph.add_node(dst, layer="fiat")
        graph.add_edge(
            src,
            dst,
            transaction_id=row["transaction_id"],
            amount=amt,
            currency=row["currency"],
            method=row["method"],
            timestamp=row["timestamp"],
            status=row["status"],
        )

    if wallet_df is not None and not wallet_df.empty:
        # Link simulated exchange on-ramp to first synthetic wallet node
        if "CRYPTO_EXCH_SIM_01" in graph:
            first_wallet = str(wallet_df.iloc[0]["source_wallet"]).strip()
            graph.add_node(first_wallet, layer="crypto_sim")
            graph.add_edge(
                "CRYPTO_EXCH_SIM_01",
                first_wallet,
                transaction_id="ONRAMP-SIM",
                amount=float(wallet_df.iloc[0]["fiat_equivalent_inr"]),
                currency="INR->SIM-USDT",
                method="SIM_EXCHANGE",
                timestamp=str(wallet_df.iloc[0]["timestamp"]),
                status="SIMULATED",
            )
        for _, wrow in wallet_df.iterrows():
            wsrc = str(wrow["source_wallet"]).strip()
            wdst = str(wrow["destination_wallet"]).strip()
            graph.add_node(wsrc, layer="crypto_sim")
            graph.add_node(wdst, layer="crypto_sim")
            graph.add_edge(
                wsrc,
                wdst,
                transaction_id=wrow["transfer_id"],
                amount=float(wrow["fiat_equivalent_inr"]),
                currency=wrow["token_symbol"],
                method="SIM_WALLET_HOP",
                timestamp=str(wrow["timestamp"]),
                status="SIMULATED",
            )

    return graph


def trace_fund_paths(graph: nx.DiGraph, source_account: str = "ASTERION_CORP_01") -> list[list[str]]:
    """Return all simple paths from the victim account to terminal sink nodes."""
    if source_account not in graph:
        return []
    sinks = [node for node in graph.nodes if graph.out_degree(node) == 0 and node != source_account]
    paths: list[list[str]] = []
    for sink in sinks:
        for path in nx.all_simple_paths(graph, source=source_account, target=sink):
            paths.append(path)
    return sorted(paths)


def detect_rapid_transfers(
    transactions_df: pd.DataFrame,
    threshold_seconds: int = 900,
) -> list[dict[str, Any]]:
    """Identify outgoing transfers occurring shortly after an incoming deposit."""
    rapid_events: list[dict[str, Any]] = []
    ordered = transactions_df.sort_values("timestamp")

    inbound_times: dict[str, list[tuple[str, datetime]]] = {}
    for _, row in ordered.iterrows():
        ts = _to_utc(str(row["timestamp"]))
        src = str(row["source"]).strip()
        dst = str(row["destination"]).strip()
        txn_id = str(row["transaction_id"]).strip()

        for in_txn_id, in_ts in inbound_times.get(src, []):
            delta = int((ts - in_ts).total_seconds())
            if 0 <= delta <= threshold_seconds:
                rapid_events.append(
                    {
                        "account": src,
                        "inbound_txn": in_txn_id,
                        "outbound_txn": txn_id,
                        "destination": dst,
                        "amount_inr": float(row["amount_numeric"]),
                        "elapsed_seconds": delta,
                        "status": row["status"],
                    }
                )
        inbound_times.setdefault(dst, []).append((txn_id, ts))

    return rapid_events


def detect_account_splitting(transactions_df: pd.DataFrame, min_targets: int = 2) -> list[dict[str, Any]]:
    """Detect accounts that split received funds across multiple distinct destination accounts."""
    splitting: list[dict[str, Any]] = []
    for src, group in transactions_df.groupby("source"):
        unique_targets = sorted(group["destination"].unique().tolist())
        if len(unique_targets) >= min_targets:
            splitting.append(
                {
                    "source_account": src,
                    "distinct_destinations": unique_targets,
                    "outgoing_count": int(len(group)),
                    "total_split_inr": round(float(group["amount_numeric"].sum()), 2),
                }
            )
    return splitting


def render_fund_flow_figure(graph: nx.DiGraph, output_path: Path) -> Path:
    """Render a clean hierarchical left-to-right fund-flow graph image for the report."""
    from matplotlib.patches import Patch

    output_path.parent.mkdir(parents=True, exist_ok=True)
    fig, ax = plt.subplots(figsize=(15.5, 6.2))

    # Deterministic hierarchical coordinates prevent overlapping edges and labels
    pos_map: dict[str, tuple[float, float]] = {
        "ASTERION_CORP_01": (0.0, 0.0),
        "MULE_ACC_01": (2.6, 0.0),
        "MULE_ACC_02": (5.4, -1.15),
        "MULE_ACC_03": (5.4, 1.15),
        "MULE_ACC_04": (8.6, 1.15),
        "CRYPTO_EXCH_SIM_01": (8.6, -1.15),
        "HYDRA-SIM-EXCH-ONRAMP-0001": (11.8, -1.15),
        "HYDRA-SIM-WALLET-ALPHA-0000": (15.0, -1.15),
        "HYDRA-SIM-WALLET-EXIT-9999": (18.2, -1.15),
    }
    fallback_pos = nx.spring_layout(graph, seed=42)
    pos = {node: pos_map.get(node, fallback_pos[node]) for node in graph.nodes}

    node_colors = []
    for node in graph.nodes:
        if node == "ASTERION_CORP_01":
            node_colors.append("#1f5a99")
        elif node == "MULE_ACC_04":
            node_colors.append("#2f855a")
        elif "CRYPTO" in node or "HYDRA-SIM" in node:
            node_colors.append("#9b2c2c")
        else:
            node_colors.append("#d97706")

    nx.draw_networkx_nodes(
        graph, pos, node_color=node_colors, node_size=1450, edgecolors="#1a202c", linewidths=1.2, ax=ax
    )
    nx.draw_networkx_edges(
        graph,
        pos,
        arrows=True,
        arrowstyle="-|>",
        arrowsize=18,
        edge_color="#4a5568",
        width=1.8,
        min_source_margin=24,
        min_target_margin=24,
        ax=ax,
    )

    for node, (x, y) in pos.items():
        y_offset = -0.36 if y <= 0 else 0.36
        va = "top" if y <= 0 else "bottom"
        short_label = node.replace("HYDRA-SIM-", "SIM-\n")
        ax.text(
            x,
            y + y_offset,
            short_label,
            ha="center",
            va=va,
            fontsize=8.0,
            fontweight="bold",
            color="#1a202c",
            bbox={"boxstyle": "round,pad=0.22", "fc": "#f8fafc", "ec": "#cbd5e0", "lw": 0.8},
        )

    edge_labels = {
        (u, v): f"{d['transaction_id']}\nINR {d['amount']:,.0f}\n({d['status']})"
        for u, v, d in graph.edges(data=True)
    }
    nx.draw_networkx_edge_labels(
        graph,
        pos,
        edge_labels=edge_labels,
        font_size=7.0,
        bbox={"boxstyle": "round,pad=0.18", "fc": "white", "ec": "none", "alpha": 0.92},
        ax=ax,
    )

    legend_items = [
        Patch(facecolor="#1f5a99", edgecolor="#1a202c", label="Victim Account"),
        Patch(facecolor="#d97706", edgecolor="#1a202c", label="Suspected Mule Account (Frozen)"),
        Patch(facecolor="#2f855a", edgecolor="#1a202c", label="Intercepted Hold in Transit"),
        Patch(facecolor="#9b2c2c", edgecolor="#1a202c", label="Simulated Crypto On-Ramp / Wallet"),
    ]
    ax.legend(handles=legend_items, loc="upper left", frameon=True, fontsize=8.5)
    ax.set_title(
        "Operation Hydra — Simulated Fraudulent Fund-Flow Graph (INR 450,000 Outflow)",
        fontsize=12.5,
        fontweight="bold",
        pad=14,
    )
    ax.set_xlim(-1.2, 19.5)
    ax.set_ylim(-2.3, 2.2)
    ax.axis("off")
    fig.tight_layout()
    fig.savefig(output_path, dpi=180, bbox_inches="tight")
    plt.close(fig)
    return output_path
