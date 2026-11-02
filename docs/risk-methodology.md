# Risk methodology

RiskProof deliberately does **not** compute a single opaque score. It produces
**separated, explainable dimensions** and one **documented decision table** for
remediation priority. Every dimension carries its rationale in the output.

## The dimensions

| Dimension | Question it answers | Sources |
| --- | --- | --- |
| **Vulnerability severity** | How bad is the bug itself? | Scanner severity, CVSS v3 base score/vector, Tenable VPR |
| **Exploitation likelihood** | How likely is this CVE to be exploited? | CISA KEV listing, FIRST EPSS |
| **Environmental exposure** | Can attackers reach it here? | Asset context (`internet_facing`), authorized validation results |
| **Verified applicability** | Does the bug actually affect this system? | Scanner claims, plugin output vs. observed versions, `verify_applicability` |
| **Business impact** | What would compromise mean here? | Asset criticality, environment, owner |
| **Evidence confidence** | How much do we trust the picture? | Provenance of every evidence item (live vs. SAMPLE, direct vs. inferred, failed checks) |
| **Remediation priority** | What should we do first? | The decision table below |

## Exploitation likelihood levels

| Level | Meaning | Trigger |
| --- | --- | --- |
| `observed_in_the_wild` | Exploitation of this CVE observed globally | CVE listed in CISA KEV |
| `elevated` | High statistical likelihood | EPSS ≥ 0.1 (≥ 0.5 noted as "very high") |
| `moderate` | Non-trivial statistical likelihood | EPSS ≥ 0.01 |
| `low` | Low statistical likelihood | EPSS < 0.01 |
| `unknown` | No usable intel | No EPSS/KEV data for the CVEs |

**EPSS caveat (enforced in code and prose):** EPSS is the probability that a CVE
is exploited *somewhere in the wild* within the next 30 days. It is a property
of the CVE, never evidence about a specific system.

## Priority decision table

Rules are evaluated **in order; first match wins**. VPR adjustments and the
false-positive cap are applied afterwards. The rationale lines returned by the
API name the matched rule.

| # | Condition | Priority |
| --- | --- | --- |
| 1 | KEV-listed **and** internet-facing | P1 |
| 2 | KEV-listed **and** business-critical asset | P1 |
| 3 | Likelihood `elevated` **and** exposure verified/internet-facing | P1 |
| 4 | Likelihood `elevated` **and** business-critical asset | P1 |
| 5 | KEV-listed (otherwise) | P2 |
| 6 | Likelihood `elevated` (otherwise) | P2 |
| 7 | Severity critical/high **and** internet-facing | P2 |
| 8 | Severity critical/high | P2 |
| 9 | Severity medium | P3 |
| 10 | Severity low/info | P4 |
| 11 | Insufficient evidence | P3 + human-review note |

Post-rules (transparent, each adds a rationale line):

- **VPR lift:** VPR ≥ 7 lifts P3 → P2; VPR ≥ 9 lifts P4 → P3.
- **False-positive cap:** applicability `suspected_not_affected` caps priority
  at P3. It **never zeroes or suppresses** a finding — a human decides.

## Risk score and ranking

Alongside (never instead of) the P1-P4 decision table, `investigate_finding`
returns a **risk score** per finding. It is not opaque: it is a published
additive table, and every point is attributable to a visible component.

| Component | Points | Rule |
| --- | --- | --- |
| GreyNoise active exploitation | 0 or 30 | malicious-tagged scanning/exploitation seen by GreyNoise in the lookback window (default 3 days) |
| CISA KEV | 0 or 30 | the CVE is KEV-listed |
| EPSS | 0-25 | `round(EPSS x 25)` |
| Affected assets | 0-15 | distinct assets with an **open** finding for this vulnerability: 1 = 2, 2-4 = 5, 5-19 = 9, 20-99 = 12, 100+ = 15 |

- A **vulnerability** is a CVE (a finding with several CVEs takes its highest-ranked
  one and names it) or, with no CVE, the scanner plugin.
- **Availability:** an input that could not be read adds no points and is listed as
  unavailable (`inputs_available`, e.g. 3 of 4). GreyNoise `no_data` (no tag for the
  CVE) and `not_checked` (budget, rate limit, error, not configured) are gaps,
  never low risk. KEV absence in a SAMPLE catalog is not an available input.
- **`exploited_now`** is true when GreyNoise `observed` malicious activity or the CVE is
  KEV-listed. The **ranking** is `(exploited_now, score, affected assets)`, highest
  first, so an actively exploited vulnerability outranks a higher-scoring quiet one.
- **GreyNoise caveat:** a reading means scanning or exploitation attempts against
  GreyNoise's own sensors. It is not evidence that a specific asset was targeted,
  reachable, or compromised, and no tag does not mean not exploited.
- The P1-P4 priority is unchanged by the score. Weights live in
  `engine/riskscore.py`; change them there and here together.

## Evidence confidence

| Label | Meaning |
| --- | --- |
| `confirmed` | Direct evidence: scanner report, live feed values, successful authorized check |
| `inferred` | Conclusion derived from evidence (the derivation is stated) |
| `inconclusive` | Mixed/partial evidence, incl. SAMPLE-fixture intel |
| `missing` | Information absent (recorded as an open question) |
| `verification_failed` | An authorized check ran and could not complete |

Negative or inconclusive validation results are recorded as evidence with their
own confidence; they never automatically downgrade applicability or suppress the
finding. Applicability `suspected_not_affected` (e.g., banner version mismatch)
is flagged for human review instead.

## Worked example (bundled demo data)

- **Log4Shell on prod-web-01** (critical, internet-facing): KEV `Known` +
  internet-facing → **P1**, rationale "KEV-listed and internet-facing".
- **regreSSHion on prod-web-01**: high EPSS, **not** KEV-listed → likelihood
  `elevated` + internet-facing → **P1** via rule 3.
- **Zerologon on corp-db-02** (critical, internal): KEV + critical asset → **P1**
  via rule 2, even though CVSS base is only 5.5 — severity alone would have
  buried it.
- **Terrapin on corp-db-02**: medium severity, moderate EPSS, no KEV → **P3**.
- **TCP timestamps on dev-jump-03**: info, no CVE → **P4**, track only.
