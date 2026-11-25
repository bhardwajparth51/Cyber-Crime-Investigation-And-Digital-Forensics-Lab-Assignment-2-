"""End-to-end offline forensic analysis pipeline for Operation Hydra."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

import pandas as pd

ROOT_DIR = Path(__file__).resolve().parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from src.common.evidence_manifest import verify_manifest
from src.correlation.evidence_correlator import build_evidence_correlation
from src.correlation.timeline_builder import build_unified_timeline, collect_events_from_evidence
from src.email_analysis.phishing_analyzer import analyze_email_directory
from src.financial_analysis.fund_tracer import (
    build_transaction_graph,
    detect_account_splitting,
    detect_rapid_transfers,
    render_fund_flow_figure,
    trace_fund_paths,
)
from src.financial_analysis.mule_account_detector import identify_suspected_mule_accounts
from src.financial_analysis.transaction_analyzer import (
    calculate_financial_impact,
    validate_transactions,
)
from src.infrastructure.dns_lookup import analyze_synthetic_dns
from src.infrastructure.ip_analyzer import analyze_ip_observations
from src.infrastructure.whois_lookup import analyze_synthetic_whois
from src.malware_analysis.behavior_analyzer import analyze_simulated_behavior
from src.malware_analysis.ioc_extractor import extract_iocs
from src.malware_analysis.payload_decoder import decode_payload_fixture

DEFAULT_FIXTURE_PATH = (
    ROOT_DIR / "samples" / "malware" / "harmless-simulator" / "encoded_payload_fixture.txt"
)


def _write_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")


def run_pipeline(
    evidence_dir: Path,
    reports_dir: Path,
    fixture_path: Path = DEFAULT_FIXTURE_PATH,
    skip_verify: bool = False,
) -> dict[str, Any]:
    """Execute the full offline Operation Hydra investigation pipeline."""
    manifest_path = evidence_dir / "manifest.json"
    if not skip_verify:
        verification = verify_manifest(evidence_dir, manifest_path)
        if not verification.verified:
            raise RuntimeError(
                f"Evidence integrity check failed: mismatches={verification.mismatches}, "
                f"missing={verification.missing_files}, untracked={verification.untracked_files}"
            )

    generated_dir = reports_dir / "generated"
    figures_dir = reports_dir / "figures"

    # 1. Email & infrastructure forensics
    email_findings = analyze_email_directory(evidence_dir / "emails")
    dns_findings = analyze_synthetic_dns(evidence_dir / "network" / "dns-records.json")
    whois_findings = analyze_synthetic_whois(evidence_dir / "network" / "dns-records.json")
    ip_findings = analyze_ip_observations(
        evidence_dir / "network" / "ip-observations.csv",
        evidence_dir / "network" / "connection-logs.json",
    )

    # 2. Safe malware behavior analysis & IOC extraction
    decoded_fixture = decode_payload_fixture(fixture_path)
    malware_findings = analyze_simulated_behavior(
        evidence_dir / "endpoint" / "execution-events.json",
        evidence_dir / "endpoint" / "malware-observations.json",
    )
    ioc_report = extract_iocs(
        email_findings=email_findings,
        execution_events_path=evidence_dir / "endpoint" / "execution-events.json",
        malware_observations_path=evidence_dir / "endpoint" / "malware-observations.json",
        connection_logs_path=evidence_dir / "network" / "connection-logs.json",
        ip_observations_path=evidence_dir / "network" / "ip-observations.csv",
        decoded_fixture=decoded_fixture,
    )

    # 3. Financial fraud reconstruction
    txn_csv = evidence_dir / "financial" / "transactions.csv"
    ledger_csv = evidence_dir / "financial" / "account-ledger.csv"
    wallet_csv = evidence_dir / "financial" / "wallet-transfers.csv"

    txn_df, validation = validate_transactions(txn_csv)
    wallet_df = pd.read_csv(wallet_csv)
    graph = build_transaction_graph(txn_df, wallet_df)
    fund_paths = trace_fund_paths(graph)
    rapid_transfers = detect_rapid_transfers(txn_df)
    splitting = detect_account_splitting(txn_df)
    mule_reports = identify_suspected_mule_accounts(txn_df)
    financial_impact = calculate_financial_impact(txn_csv, ledger_csv, wallet_csv)
    figure_path = render_fund_flow_figure(graph, figures_dir / "fund-flow-graph.png")

    financial_summary = {
        "validation_passed": validation.is_valid,
        "impact": financial_impact,
        "fund_flow_paths": fund_paths,
        "rapid_transfers": rapid_transfers,
        "account_splitting": splitting,
        "suspected_mule_accounts": mule_reports,
        "graph_figure": str(figure_path.relative_to(ROOT_DIR)),
    }

    # 4. Cross-source timeline & correlation
    raw_events = collect_events_from_evidence(
        email_findings=email_findings,
        dns_records_path=evidence_dir / "network" / "dns-records.json",
        connection_logs_path=evidence_dir / "network" / "connection-logs.json",
        execution_events_path=evidence_dir / "endpoint" / "execution-events.json",
        login_events_path=evidence_dir / "authentication" / "login-events.csv",
        transactions_path=txn_csv,
        wallet_transfers_path=wallet_csv,
    )
    timeline_report = build_unified_timeline(raw_events)
    correlation_report = build_evidence_correlation(
        email_findings=email_findings,
        malware_analysis=malware_findings,
        financial_impact=financial_impact,
        mule_reports=mule_reports,
        timeline_report=timeline_report,
    )

    # 5. Persist derived analysis outputs separately from original evidence
    _write_json(generated_dir / "email-analysis.json", email_findings)
    _write_json(
        generated_dir / "infrastructure-analysis.json",
        {"dns": dns_findings, "whois": whois_findings, "ip_analysis": ip_findings},
    )
    _write_json(
        generated_dir / "malware-analysis.json",
        {"behavior": malware_findings, "decoded_fixture": decoded_fixture},
    )
    _write_json(generated_dir / "financial-analysis.json", financial_summary)
    _write_json(generated_dir / "timeline.json", timeline_report)
    _write_json(generated_dir / "correlation-summary.json", correlation_report)
    _write_json(reports_dir / "ioc-report.json", ioc_report)

    return {
        "emails_analyzed": len(email_findings),
        "ioc_count": ioc_report["total_iocs"],
        "malware_classification": malware_findings["primary_classification"],
        "financial_impact": financial_impact,
        "timeline_events": timeline_report["sequenced_event_count"],
        "correlation_count": len(correlation_report["relationship_table"]),
        "outputs_dir": str(generated_dir),
        "ioc_report_path": str(reports_dir / "ioc-report.json"),
        "figure_path": str(figure_path),
    }


def _display_path(path: Path) -> str:
    try:
        return str(path.resolve().relative_to(ROOT_DIR))
    except ValueError:
        return str(path)


def main() -> int:
    parser = argparse.ArgumentParser(description="Run the Operation Hydra offline analysis pipeline.")
    parser.add_argument("--evidence-dir", type=Path, default=ROOT_DIR / "evidence")
    parser.add_argument("--reports-dir", type=Path, default=ROOT_DIR / "reports")
    parser.add_argument("--skip-verify", action="store_true")
    args = parser.parse_args()

    summary = run_pipeline(args.evidence_dir, args.reports_dir, skip_verify=args.skip_verify)
    impact = summary["financial_impact"]

    print("=== Operation Hydra Investigation Summary ===")
    print(f"Evidence integrity : {'SKIPPED' if args.skip_verify else 'VERIFIED'}")
    print(f"Emails analyzed    : {summary['emails_analyzed']} (all synthetic)")
    print(f"Malware class      : {summary['malware_classification']}")
    print(f"Total IOCs         : {summary['ioc_count']} -> {_display_path(Path(summary['ioc_report_path']))}")
    print(
        "Financial impact   : "
        f"INR {impact['total_fraudulent_outflow_inr']:,.2f} outflow | "
        f"INR {impact['frozen_recoverable_inr']:,.2f} frozen/recoverable | "
        f"INR {impact['unrecovered_loss_inr']:,.2f} unrecovered"
    )
    print(f"Timeline events    : {summary['timeline_events']} sequenced UTC events")
    print(f"Derived outputs    : {_display_path(Path(summary['outputs_dir']))}")
    print(f"Fund-flow figure   : {_display_path(Path(summary['figure_path']))}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
