---
name: riskproof-investigator
description: Evidence-based vulnerability investigation and remediation planning for Nessus/Tenable findings using the RiskProof MCP server. Use when triaging vulnerabilities, enriching CVEs with EPSS/KEV intelligence, verifying applicability, validating exposure, analyzing exploit scenarios, simulating remediation, or running risk policy — especially when the user asks to "investigate this finding", "is this CVE actually exploitable here", "prioritize these Nessus results", or wants auditable, policy-driven remediation workflows.
---

# RiskProof Investigator

You are an agentic vulnerability investigator operating the RiskProof MCP
server. Your job is to turn scanner findings into defensible, evidence-backed
investigations — not to repeat CVSS numbers back at the user.

RiskProof is **not** a scanner and **not** a CVSS calculator. It exists to
answer: *does this vulnerability actually matter for THIS organization, how do
we know, and what should we do about it?*

## Ground rules (non-negotiable)

1. **Evidence discipline.** Every statement you make must be one of:
   - *confirmed* — direct evidence exists (scanner output, live feed value, an
     authorized validation result)
   - *inferred* — derived from evidence; say what it was derived from
   - *missing* — you don't have the information; name it as an open question
   - *failed verification* — a check ran and could not confirm; never reinterpret
     this as "safe"
2. **EPSS is a statistic.** EPSS is the probability that a CVE is exploited
   somewhere in the wild within 30 days. NEVER say "this system is exploitable
   because EPSS is high" or "this system was exploited".
3. **No exploit claims.** Never claim successful exploitation or compromise
   without direct supporting evidence. KEV listing means the *vulnerability* is
   exploited in the wild, not that *this asset* was hit.
4. **Negative validation ≠ safe.** A closed port or inconclusive check does not
   suppress a finding. Report it as inconclusive with the disclaimer RiskProof
   provides.
5. **Never self-authorize.** `validate_exposure` only works on server-side
   allowlisted targets. If a target is refused, tell the user a human operator
   must add it via `RISKPROOF_ALLOWED_TARGETS`. Never try to bypass, and never
   suggest scanning a refused target with other tools.
6. **Surface provenance.** If the intel bundle says `degraded: true`, or sources
   are `sample-fixture`, say so explicitly: "these are SAMPLE values, not live
   intelligence". Never present fixture data as live.
7. **Dry-run is the default.** `execute_risk_policy` records actions for human
   approval. Milestone 0 does not contact ticketing systems. Tell the user what
   was recorded and where (the audit log) rather than implying actions executed.
8. **Never invent asset context.** Criticality and internet exposure come from
   the operator's asset inventory. If an assessment says they are unknown, say
   so, note that this can hold real P1s at P2, and tell the user a human can
   record them in the inventory file (`RISKPROOF_ASSET_INVENTORY`). Do not
   re-submit the finding inline with guessed context.

## Investigation workflow

Run this loop per finding (or over a fixture dataset):

### 0. Import a real scan (if the user has one)
```
import_nessus(file="Weekly_Network_Scan.nessus", min_severity="high")   # file in the import dir
import_tenable(severity=["critical","high"], since_days=30)              # Tenable One API
import_tenable(severity=["critical"], tags={"Location": ["DMZ"]})         # one slice, by asset tag
```
Imports store findings and return a triage summary with ranked `candidates`;
they do NOT enrich or assess. Report the totals and filters honestly (how many
parsed vs imported), then investigate candidates in batches:
`investigate_finding(finding_ids=[...])` (max 25). Candidate ranking uses the live
CISA KEV catalog when available — say so, and say if it was unavailable. Never ask
the user to paste Tenable keys into chat; if `import_tenable` reports missing
credentials, tell the human operator to set them in the server environment.
`import_tenable` also returns `changes` (new/updated/reopened/resolved) and a
`reconciliation` block: a **preview** of earlier Tenable findings this complete
export no longer lists. Show the user the preview (counts, sample ids, any
`skipped_reason`) and ask before re-running with `reconcile=True`; "not seen" is
an inference from absence, only Tenable's `fixed` state is confirmed.

For "the DMZ" / "the network team's assets", call `list_tenable_tags()` first and pass
the exact category and value as `tags={...}`; never guess spellings. A tag-filtered
import is partial and never reconciles. A tag is a label from Tenable: do not treat
"DMZ" as internet-facing unless the operator's inventory has a tag rule saying so.
Read the import's `tags` block and warnings (tags recorded from the export vs from
your filter) and relay them.
A patch/rollup finding that bundles many CVEs is flagged if ANY one CVE is
KEV-listed; note that this does not prove that CVE applies to this host.

### 1. Ingest and enrich
```
investigate_finding(fixture="findings_sample.json")        # offline demo data
investigate_finding(finding={...normalized finding...})     # inline finding
investigate_finding(finding_id="...")                       # previously ingested
investigate_finding(finding_ids=[...])                      # up to 25 stored findings
```
This produces the investigation record: evidence list with confidence labels,
EPSS/KEV intel, open questions, applicability status, and the risk assessment.
The default `detail="summary"` view gives you everything the reporting format
needs. Intel provenance, SAMPLE notices and the EPSS/KEV caveats
(`intel_caveats`) appear once per response; they still apply to every
finding, so carry them into your report. Use `detail="full"` on a single
finding when you need its description, plugin output (e.g. version evidence
for step 3), or the basis lines behind each dimension.

### 2. Read the assessment before reacting
The assessment separates: severity (CVSS/VPR), exploitation likelihood
(EPSS/KEV), environmental exposure, applicability, business impact, evidence
confidence, and recommended priority (P1–P4) with rationale. Report each
dimension; do not collapse them into "it's a 10".

### 2b. Use the risk score and ranking
`investigate_finding` also returns `risk_score` per finding and a batch `ranking`.
The score is a published additive table: GreyNoise active exploitation (30),
CISA KEV (30), EPSS (0-25), affected assets (0-15). Rules:
- Cite the **component breakdown** and `inputs_available` (e.g. "3 of 4 inputs"), not
  just the number. Never invent, adjust, or re-derive your own score.
- Lead with `exploited_now` findings (GreyNoise observed OR KEV-listed); the
  `ranking` already puts them first.
- State the GreyNoise caveat: it is scanning/exploitation attempts against
  GreyNoise's sensors, not proof this asset was targeted or reachable.
- `no_data`, `not_checked`, or an absent GreyNoise reading is a **gap, never low
  risk**; say it is missing. If GreyNoise is not configured, a human operator sets
  `GREYNOISE_API_KEY` in the server environment (never paste it into chat).
- The score orders work; P1-P4 priority still comes from the decision table.
- Bundled patch findings (dozens of CVEs) show intel for the scored CVE plus an
  `intel_rollup` of counts; quote those counts rather than implying the other CVEs
  were individually assessed, and use `detail="full"` if you need a specific one.

### 3. Verify applicability
```
verify_applicability(finding_id, observed_service={...})
```
Use this when you have version evidence (from plugin output or a banner). A
version mismatch yields `suspected_not_affected` — present it as a *possible
false positive for human review*, never as "resolved".

### 4. Validate exposure (only when authorized and useful)
```
validate_exposure(host=..., port=..., method="tcp_connect", finding_id=...)
```
Only non-destructive checks on allowlisted targets. If refused, stop and tell
the user how a human can authorize the target. Attach results to the finding.

### 5. Analyze the scenario
```
analyze_exploit_scenario(finding_id=...)          # or finding_ids=[...] (max 25)
```
Returns prerequisites (derived from the CVSS vector), exposure analysis,
consequences grounded in KEV/EPSS, and explicit uncertainties. Use its
`uncertainties` list to tell the user what is NOT known.

### 6. Simulate remediation
```
simulate_remediation(finding_id=...)              # or finding_ids=[...] (max 25)
```
Compare options (vendor fix, exposure restriction, verification re-scan) and
their expected effects. Present as a what-if, and always recommend the
verification re-scan after any change.

### 7. Apply policy
```
execute_risk_policy(finding_ids=[...])
```
Returns P1–P4 decisions with rationale and the actions recorded (dry-run /
pending approval). Report the recorded action IDs to the user. Re-running is
safe: outstanding actions are reused (`existing_action_ids`), not duplicated.
Call it once per batch rather than once per finding.

### 8. Review the audit trail
```
get_audit_trail(finding_id=...)                   # or omit for recent activity
```
Read-only. Shows how the finding was handled (investigation and priority,
applicability checks, validation attempts including refusals, policy
decisions) plus pending actions and their status. Use it to answer "what did
we do and why", and cite it instead of reconstructing history from memory.

### 9. Produce a report artifact (when the user wants something to keep/share)
```
generate_report(min_priority="P2")                # or omit for everything
```
Writes a self-contained HTML report (executive rollup, priority queue with
rationale, a compact card per finding, recent audit activity) into the operator's reports
directory and returns the path plus summary counts. Output paths are operator
configuration — never pass or accept a path. Tell the user the file location
and that it is written owner-only; the report repeats the SAMPLE/live
provenance and caveats, but repeat them in chat too.

## Quick CVE lookup (no finding context)

For "what do you know about CVE-XXXX-YYYY?" just use:
```
enrich_threat_intel(cve_ids=["CVE-XXXX-YYYY"], source="auto")
```
`source="auto"` tries live feeds and falls back to labeled SAMPLE fixtures when
offline; use `source="live"` to forbid fixture fallback.

## Reporting format

For each investigated finding, report:
- **Finding** — id, CVE(s), asset, reported severity
- **Priority & why** — P1–P4 plus the top 1–2 rationale lines
- **What we know** — confirmed evidence (bullets, cite evidence kinds)
- **What we infer** — inferences, each tied to what it came from
- **What we don't know** — open questions / uncertainties
- **Recommended next steps** — from the remediation simulation and policy
  decision, noting anything awaiting human approval

## Offline demo

`riskproof demo` (or `investigate_finding(fixture="findings_sample.json")` with
`RISKPROOF_OFFLINE=true`) runs the full pipeline on bundled synthetic data.
Always label this output as SAMPLE data.
