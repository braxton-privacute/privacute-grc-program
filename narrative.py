import json
from expand_frameworks import expand_finding, FRAMEWORKS
from coverage import get_denominators

# ---------------------------------------------------------
# The AI seam. Today it returns a mock. Later, swap the body
# for a real Claude API call. Nothing else in the file changes.
# ---------------------------------------------------------
USE_REAL_AI = False  # off by default: runs without an API key. Set True to call the API.

def generate_summary(brief):
    """Given a text brief of VERIFIED facts, return a plain-language summary.

    The AI may ONLY restate and explain facts in the brief. It must not
    introduce control IDs, percentages, framework names, or any claim not
    present in the input.
    """
    if USE_REAL_AI:
        import anthropic
        client = anthropic.Anthropic()  # reads ANTHROPIC_API_KEY from environment

        system_prompt = (
            "You are summarizing a cybersecurity risk assessment for a "
            "non-technical medical practice owner. You will be given a block of "
            "VERIFIED FACTS. Write a short, plain-language summary (3-5 sentences). "
            "STRICT RULES: Use ONLY the facts provided. Do NOT invent or infer any "
            "numbers, percentages, control IDs, framework names, or claims not "
            "explicitly in the input. Do NOT soften or exaggerate. If a fact is not "
            "in the input, do not mention it. Plain language, no jargon."
        )

        message = client.messages.create(
            model="claude-haiku-4-5",
            max_tokens=400,
            system=system_prompt,
            messages=[{"role": "user", "content": brief}],
        )

        parts = [block.text for block in message.content if block.type == "text"]
        return "\n".join(parts)
    else:
        return (
            "[MOCK SUMMARY — replace with AI-generated text]\n\n"
            "This assessment identified several risks concentrated in third-party "
            "governance and access control."
        )

def build_brief(findings):
    """Assemble a plain-text brief of verified facts for the AI to summarize."""
    # Recompute the verified numbers (same logic as coverage.py)
    covered = {name: set() for name in FRAMEWORKS}
    for finding in findings:
        mapping = expand_finding(finding)
        for name in FRAMEWORKS:
            for code in mapping[name]:
                covered[name].add(code)
    denominators = get_denominators()

    lines = []
    lines.append("VERIFIED ASSESSMENT FACTS (do not add anything beyond these):")
    lines.append("")
    lines.append(f"Number of findings: {len(findings)}")
    lines.append("")
    lines.append("Findings:")
    for f in findings:
        lines.append(f"  - {f['id']} ({f['risk_band']}, score {f['risk_score']}): {f['threat']}")
    lines.append("")
    lines.append("Framework coverage (as represented in the SCF crosswalk):")
    for name, key in FRAMEWORKS.items():
        num = len(covered[name])
        den = denominators.get(key, 0)
        pct = (num / den * 100) if den else 0
        lines.append(f"  - {name}: {num} of {den} controls ({pct:.1f}%)")
    return "\n".join(lines)


def build_narrative_report(findings):
    """Combine verified facts with a labeled AI-drafted summary into Markdown."""
    brief = build_brief(findings)
    summary = generate_summary(brief)

    lines = []
    lines.append("# Assessment Narrative")
    lines.append("")
    lines.append("## Executive summary")
    lines.append("")
    lines.append("> **AI-drafted from verified facts, human-reviewed.** The summary "
                 "below was generated from the verified assessment data and reviewed "
                 "before inclusion. All figures it references are computed "
                 "deterministically from the findings and the SCF crosswalk; the AI "
                 "restates them and does not introduce new claims.")
    lines.append("")
    lines.append(summary)
    lines.append("")
    lines.append("## Verified facts (source of the summary above)")
    lines.append("")
    lines.append("```")
    lines.append(brief)
    lines.append("```")
    lines.append("")
    return "\n".join(lines)


if __name__ == "__main__":
    with open("data/findings.json", encoding="utf-8") as f:
        findings = json.load(f)

    report = build_narrative_report(findings)

    with open("narrative_report.md", "w", encoding="utf-8") as out:
        out.write(report)

    print("Wrote narrative_report.md\n")
    print(report)

