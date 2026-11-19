# Screenshot provenance and reproduction

These PNGs are real browser captures of RiskProof's generated HTML report, not
mockups or screenshots of a connected Claude session. RiskProof has no hosted
web UI. Only bundled synthetic fixtures were used; no Tenable tenant, customer
scan, live intelligence feed, or validation target was accessed for these
captures. No remediation action was executed.

## Captured run

- Application source: [`355b4fdfa4304a1e10e44e66be47c3cc95cafae7`](https://github.com/creimer808/RiskProof/commit/355b4fdfa4304a1e10e44e66be47c3cc95cafae7), RiskProof 0.1.0.
- Report generated: **2026-11-19 20:44:16 UTC**.
- Runtime: Python **3.14.4**, dependencies installed from `uv.lock` with
  `uv sync --frozen`.
- Input: `fixtures/findings_sample.json`, which loads the bundled sample asset
  context, plus SAMPLE EPSS, KEV, and GreyNoise fixtures.
- Isolation: a disposable SQLite database, absent operator inventory, empty
  validation allowlist, offline mode, dry-run mode, and human approval required.
  Tenable and GreyNoise API keys were unset.
- Result: **5 investigated findings, 3 assets, P1=3 / P2=0 / P3=1 / P4=1**,
  with **7 actions pending approval** and no uninvestigated findings.
- Validation at capture: `pytest` reported **415 passed, 2 skipped** (the opt-in
  live-feed tests); `ruff check .` and `ruff format --check .` passed. The suite
  includes an actual stdio MCP client/server workflow using fixture data.

The report's "exploited now" labels describe **sample vulnerability-level
signals**, not proof that a demo asset was targeted, reachable, or compromised.
The numeric risk score ranks work within priority; the P1-P4 decision table is
separate and deterministic.

## Reproduce the report

From the repository root, on a POSIX shell with Python 3.12+ and `uv` installed:

```bash
uv sync --frozen

# A subshell keeps these demo-only settings out of your normal environment.
(
  set -eu
  demo_dir="$(mktemp -d "${TMPDIR:-${HOME}/.cache}/riskproof-sample.XXXXXX")"
  unset TENABLE_ACCESS_KEY TENABLE_SECRET_KEY GREYNOISE_API_KEY
  export RISKPROOF_DB_PATH="$demo_dir/demo.db"
  export RISKPROOF_FIXTURES_DIR="$PWD/fixtures"
  export RISKPROOF_ASSET_INVENTORY="$demo_dir/no-inventory.json"
  export RISKPROOF_IMPORT_DIR="$demo_dir/imports"
  export RISKPROOF_REPORTS_DIR="$demo_dir/reports"
  export RISKPROOF_OFFLINE=true
  export RISKPROOF_ALLOWED_TARGETS=''
  export RISKPROOF_DRY_RUN=true
  export RISKPROOF_REQUIRE_APPROVAL=true

  uv run --frozen riskproof demo > "$demo_dir/demo-output.json"
  uv run --frozen riskproof report --output "$demo_dir/sample-report.html"
)
```

Open the printed `sample-report.html` path in a local browser. The generated
report is self-contained and owner-readable/writable only (0600). There is no
need to start an HTTP server or connect an MCP client just to view it. Keep the
disposable directory while reviewing the report, then delete only that directory
when finished. A fresh run gets new timestamps and audit IDs; it should not be
expected to produce byte-identical files.

The demo already loads `assets_sample.json` as fixture asset context. Do **not**
point `RISKPROOF_ASSET_INVENTORY` at that file: operator inventories use the
separate `{"rules": [...]}` schema documented in [usage](../usage.md).

## Capture the views

Use a desktop Chromium browser at **1440 CSS pixels wide**, device scale factor
1, and 100% zoom. Preserve the generated content and styling. These captures
only scroll the page and expand its native disclosure controls.

| File | Viewport | View |
| --- | --- | --- |
| [`report-overview.png`](report-overview.png) | 1440 x 1104 | Page top, with all disclosure sections initially closed. Includes SAMPLE provenance, dashboard counts, asset chart, and all three asset rows. |
| [`finding-detail.png`](finding-detail.png) | 1440 x 1064 | Expand **Finding detail**, then the **Log4Shell** finding. Scroll the top of the finding card to about 16 pixels below the viewport top. |
| [`policy-audit.png`](policy-audit.png) | 1440 x 850 | Collapse **Finding detail**; expand **Open pending actions** and **Recent audit activity**. Scroll the pending-actions heading near the viewport top. |

Before replacing the images, confirm that text is readable, the entire relevant
card/table is visible, and the README captions still match the output. Never
replace these with real scan data or account screenshots without reviewing them
for hostnames, IP addresses, owners, tokens, and other sensitive information.
