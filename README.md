# Privacute — GRC & Privacy Program

A privacy and security self-assessment of **Privacute**, a Maryland-based small
business providing HIPAA privacy governance to small physician-run practices.

> **This is a real self-assessment of my own company**, not a fictional scenario.
> Findings are published deliberately: each one is either remediated or is a
> documented governance gap with no live exploit. Open findings describe missing
> *documentation*, not open technical weaknesses.

For the same pipeline applied to a fictional clinical scenario, see the
Example Family Clinic assessment: `[ADD GITHUB URL ONCE THE REPO EXISTS]`

## Why self-assess

A privacy firm that cannot assess itself has no business assessing anyone else.
This applies the same tooling, the same control mapping, and the same scoring
discipline used for client work — to its own operations, and publishes the
result including the parts that are still open.

## Findings at a glance

| ID | Area | Band | Status |
|----|------|------|--------|
| PRIV-001 | Device encryption | Low | Remediated |
| PRIV-002 | AI tool governance | Medium | Open |
| PRIV-003 | Data retention & disposal | Medium | Open |
| PRIV-004 | Third-party inventory | Low | Open |

Full detail, control mappings, and remediation in `risk_assessment.md` and
`coverage_report.md`.

## What's inside

- `data/findings.json` — the findings as structured data
- `run_pipeline.py` — validates control IDs, enriches HIPAA refs, scores, reports
- `generate_coverage_report.py` — multi-framework coverage and CSF gap analysis
- `narrative.py` — optional AI narrative layer (see below)
- `SOP.md` — the documented procedure for running a new assessment

Each finding carries: threat, vulnerability, verified SCF control IDs,
likelihood/impact/risk score, status, HIPAA references, and remediation.

## How to run

```bash
python run_pipeline.py
```

The pipeline fetches the Secure Controls Framework catalog, validates every
control ID against it, and **stops before writing anything** if any ID is
invalid. A mistyped control ID fails the run instead of shipping in a report.

Then generate the multi-framework coverage report:

```bash
python generate_coverage_report.py
```

## The AI narrative layer is optional

`narrative.py` generates a written summary grounded in an explicit
verified-facts block, so the generated language stays anchored to the assessment
data rather than inventing findings. It is **off by default** — the rest of the
pipeline runs without it and without an API key. To enable it, set
`USE_REAL_AI = True` and provide an `ANTHROPIC_API_KEY` environment variable.
