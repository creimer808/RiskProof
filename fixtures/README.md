# Fixtures

**All files in this directory are SAMPLE data** for offline demonstration and
testing. They describe a small, fictional environment (RFC1918 addresses,
`*.demo.local` hostnames) and must never be presented as live findings or live
threat intelligence.

| File | Purpose |
| --- | --- |
| `sample_scan.nessus` | A synthetic `.nessus` v2 report (3 hosts, 5 findings) used to exercise XML ingestion. |
| `findings_sample.json` | The same findings in RiskProof's normalized JSON form — the offline demo dataset. |
| `assets_sample.json` | Asset context (criticality, environment, internet-facing, owner, services) for the demo hosts. |
| `epss_sample.json` | SAMPLE FIRST EPSS API response. Values are illustrative, **not** live EPSS data. |
| `kev_sample.json` | SAMPLE CISA KEV extract containing only the demo CVEs. Absence from this file is **NOT** evidence that a CVE is absent from the real KEV catalog. |

Honesty rules enforced in code:

- Findings loaded from `findings_sample.json` are marked `source="fixture"`.
- EPSS/KEV data served from fixtures is stamped `source: "sample-fixture"` /
  `catalog: "sample"` in every response.
- The demo CLI (`riskproof demo`) prints a SAMPLE banner when offline.
