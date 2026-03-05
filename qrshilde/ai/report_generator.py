from datetime import datetime
from textwrap import indent


def build_markdown_report(analysis: dict) -> str:
    payload = analysis.get("payload", "")
    risk = analysis.get("risk_score", 0)
    verdict = analysis.get("verdict", "LOW")
    ptype = analysis.get("payload_type", "unknown")
    findings = analysis.get("findings", []) or []
    benign = analysis.get("benign", []) or []
    url_analysis = analysis.get("url_analysis")

    lines = []
    lines.append("# QR Security Analysis Report")
    lines.append("")
    lines.append(f"- Generated at: {datetime.utcnow().isoformat()} UTC")
    lines.append(f"- Payload Type: **{ptype}**")
    lines.append(f"- Verdict: **{verdict}**")
    lines.append(f"- Risk Score: **{risk}/100**")
    lines.append("")

    lines.append("## QR Content")
    lines.append("")
    lines.append("```text")
    lines.append(payload)
    lines.append("```")
    lines.append("")

    lines.append("## Findings (Rules)")
    if findings:
        for f in findings:
            lines.append(f"- {f}")
    else:
        lines.append("- No findings.")
    lines.append("")

    lines.append("## Benign Signals")
    if benign:
        for b in benign:
            lines.append(f"- {b}")
    else:
        lines.append("- None.")
    lines.append("")

    if url_analysis:
        lines.append("## URL Analysis (Rules + ML)")
        lines.append("")
        lines.append(f"- URL: `{url_analysis.get('url','')}`")
        lines.append(f"- Domain: `{url_analysis.get('domain','')}`")
        lines.append(f"- URL Risk Score: **{url_analysis.get('risk_score',0)}/100**")
        lines.append("")

        ufind = url_analysis.get("findings", []) or []
        uben = url_analysis.get("benign", []) or []
        ml = url_analysis.get("ml")

        lines.append("### URL Findings")
        if ufind:
            for x in ufind:
                lines.append(f"- {x}")
        else:
            lines.append("- None.")
        lines.append("")

        lines.append("### URL Benign Signals")
        if uben:
            for x in uben:
                lines.append(f"- {x}")
        else:
            lines.append("- None.")
        lines.append("")

        if ml:
            lines.append("### ML Output")
            lines.append(f"- Label: **{ml.get('label','')}**")
            lines.append(f"- Probability: `{ml.get('phishing_probability')}`")
            lines.append(f"- Threshold: `{ml.get('threshold')}`")
            reasons = ml.get("reasons", []) or []
            if reasons:
                lines.append("- Top Reasons:")
                for r in reasons:
                    lines.append(f"  - {r.get('feature')}: {r.get('impact')}")
            lines.append("")

    return "\n".join(lines)