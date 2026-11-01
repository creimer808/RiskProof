"""Command-line interface: `riskproof serve` (default), `demo`, `report`, `version`."""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
from pathlib import Path
from typing import Any

from riskproof import __version__


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="riskproof",
        description="RiskProof — agentic vulnerability investigation platform (MCP).",
    )
    parser.add_argument("--version", action="version", version=f"riskproof {__version__}")
    sub = parser.add_subparsers(dest="command")
    sub.add_parser("serve", help="Run the RiskProof MCP server over stdio (default).")
    demo = sub.add_parser("demo", help="Run the offline demo pipeline on bundled fixtures.")
    demo.add_argument(
        "--live",
        action="store_true",
        help="Use live EPSS/KEV feeds instead of bundled sample fixtures.",
    )
    report = sub.add_parser(
        "report", help="Write a self-contained HTML report of investigated findings."
    )
    report.add_argument(
        "--min-priority",
        choices=["P1", "P2", "P3", "P4"],
        default=None,
        help="Only include findings at this priority or more urgent.",
    )
    report.add_argument(
        "--output",
        type=Path,
        default=None,
        help="Output file (default: ./riskproof-report-<timestamp>.html).",
    )
    return parser


def _run_demo(live: bool) -> int:
    from riskproof.config import Settings
    from riskproof.engine import investigation as inv
    from riskproof.engine.policy_engine import evaluate_policy
    from riskproof.engine.remediation import simulate_remediation
    from riskproof.engine.scenario import build_exploit_scenario
    from riskproof.models.policy import RiskPolicy
    from riskproof.services import build_services

    settings = Settings(offline=not live)
    if not live:
        print(
            "=== RiskProof demo — SAMPLE fixture data, NOT live intelligence ===", file=sys.stderr
        )
    services = build_services(settings)
    reports = asyncio.run(
        inv.investigate(
            services,
            fixture="findings_sample.json",
            intel_source="fixture" if not live else "auto",
        )
    )
    out: list[dict[str, Any]] = []
    for report in reports:
        finding, record, assessment = (
            report.finding,
            report.record,
            report.assessment,
        )
        scenario = build_exploit_scenario(finding, record, assessment)
        simulation = simulate_remediation(finding, record, assessment)
        decision = evaluate_policy(
            finding,
            record,
            assessment,
            RiskPolicy(),
            services.settings,
            services.audit,
            services.pending,
        )
        out.append(
            {
                "finding_id": finding.finding_id,
                "cves": finding.cve_ids,
                "asset": finding.asset.asset_id,
                "assessment": assessment.model_dump(mode="json"),
                "applicability": record.applicability.value,
                "evidence_count": len(record.evidence),
                "scenario_likelihood": scenario.exploitation_likelihood.value,
                "recommended_remediation": simulation.recommended_option_id,
                "policy_priority": decision.priority.value if decision.priority else None,
                "policy_rationale": decision.priority_rationale,
            }
        )
    print(json.dumps(out, indent=2))
    print(
        "\n=== demo complete: findings, intel, scenarios, and policy decisions above. "
        "All data labeled SAMPLE when offline. ===",
        file=sys.stderr,
    )
    return 0


def _run_report(min_priority: str | None, output: Path | None) -> int:
    from riskproof.config import load_settings
    from riskproof.engine import report as report_engine
    from riskproof.services import build_services

    settings = load_settings()
    services = build_services(settings)
    try:
        data = report_engine.build_report(services, min_priority)
        page = report_engine.render_html(data)
        target = output or report_engine.default_report_path(Path.cwd(), data.generated_at)
        written = report_engine.write_report_file(page, target)
        summary = data.summary
    finally:
        services.db.close()
    print(f"Report written: {written}")
    print(
        f"{summary.shown} of {summary.investigated_total} investigated findings in scope; "
        f"P1={summary.by_priority.get('P1', 0)} P2={summary.by_priority.get('P2', 0)} "
        f"P3={summary.by_priority.get('P3', 0)} P4={summary.by_priority.get('P4', 0)}; "
        f"{summary.uninvestigated} imported findings not yet investigated."
    )
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    if args.command == "demo":
        return _run_demo(live=args.live)
    if args.command == "report":
        return _run_report(args.min_priority, args.output)
    # serve (explicit or default)
    from riskproof.server import main as serve_main

    serve_main()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
