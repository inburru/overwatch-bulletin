"""
Overwatch Daily OSINT Bulletin
iGuardSA / Overwatch Intelligence
Runs via GitHub Actions every morning at 06:00 SAST (04:00 UTC)
"""

import os
import json
import smtplib
import anthropic
from datetime import datetime, timezone, timedelta
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from pathlib import Path

# ── CONFIG ────────────────────────────────────────────────────────────────────

RECIPIENT_EMAIL = "inburru@gmail.com"
SENDER_EMAIL    = os.environ["GMAIL_ADDRESS"]
GMAIL_APP_PWD   = os.environ["GMAIL_APP_PASSWORD"]
ANTHROPIC_KEY   = os.environ["ANTHROPIC_API_KEY"]

SAST = timezone(timedelta(hours=2))
TODAY = datetime.now(SAST).strftime("%Y-%m-%d")
TODAY_DISPLAY = datetime.now(SAST).strftime("%A, %d %B %Y")

FOCUS_TOPICS = (
    "Barloworld, Ingrain, Zahid Group, Vostochnaya Technica, South Africa, "
    "ransomware, BEC fraud, JSE-listed companies, SAPS, financial sector, "
    "SA government, SA critical infrastructure"
)

TIER1_SOURCES = [
    "Cisco Talos", "The DFIR Report", "Mandiant", "CISA KEV",
    "Ransomware tracking feeds", "SOCRadar", "ISC SANS Stormcast", "MSRC/MSTIC"
]

SEARCH_QUERIES = [
    f"ransomware attack South Africa Africa {TODAY[:7]}",
    f"CISA known exploited vulnerabilities KEV {TODAY[:7]}",
    f"South Africa cyber security breach attack {TODAY[:7]}",
    f"critical CVE exploitation June 2026",
    f"BEC phishing South Africa financial sector 2026",
    f"APT nation state cyberattack Africa 2026",
    f"Barloworld OR Ingrain OR 'Zahid Group' cyber security 2026",
    f"new malware campaign threat actor {TODAY[:7]}",
]

BULLETIN_SCHEMA = """{
  "generated_at": "YYYY-MM-DD",
  "mode": "live",
  "overall_threat_level": "HIGH|MEDIUM|LOW",
  "executive_summary": "2-3 sharp sentences on the most critical findings",
  "threat_levels": {
    "ransomware": 0-100,
    "bec_phishing": 0-100,
    "state_sponsored": 0-100,
    "supply_chain": 0-100
  },
  "sectors_at_risk": ["sector1", "sector2"],
  "findings": [
    {
      "severity": "CRITICAL|HIGH|MEDIUM|INFO",
      "category": "Ransomware|APT|Vulnerability|BEC|Malware|DDoS|Africa-specific|Dark Web",
      "title": "concise finding title",
      "source": "source name",
      "body": "2-3 sentences with specific technical details, threat actor names, affected systems",
      "live": true,
      "sa_relevant": true|false,
      "sa_reason": "why relevant to SA or focus targets (only if sa_relevant true)",
      "iocs": ["indicator1"],
      "tags": ["tag1"]
    }
  ],
  "iocs": [
    {"type": "CVE|IP|DOMAIN|HASH|ACTOR|MALWARE|MITIGATION|PATCH", "value": "value", "context": "brief context"}
  ],
  "source_log": [
    {"source": "source name", "status": "ok|limited|unavailable", "items_found": 0, "note": "brief note"}
  ]
}"""


# ── SEARCH ────────────────────────────────────────────────────────────────────

def run_live_searches(client: anthropic.Anthropic) -> str:
    """Run all search queries and collect raw intelligence."""
    print(f"[{datetime.now(SAST).strftime('%H:%M:%S')}] Running {len(SEARCH_QUERIES)} live searches...")
    collected = []

    for i, query in enumerate(SEARCH_QUERIES, 1):
        print(f"  [{i}/{len(SEARCH_QUERIES)}] {query}")
        try:
            response = client.messages.create(
                model="claude-sonnet-4-20250514",
                max_tokens=800,
                tools=[{"type": "web_search_20250305", "name": "web_search"}],
                messages=[{
                    "role": "user",
                    "content": (
                        f'Search for: "{query}". '
                        f'Return the 3 most relevant findings as a JSON array: '
                        f'[{{"title":"...","source":"...","snippet":"...","url":"..."}}]. '
                        f'Return only the JSON array, no other text.'
                    )
                }]
            )
            text = "".join(b.text for b in response.content if hasattr(b, "text"))
            # Extract JSON array
            start = text.find("[")
            end = text.rfind("]") + 1
            if start >= 0 and end > start:
                items = json.loads(text[start:end])
                for item in items:
                    item["query"] = query
                    collected.append(item)
        except Exception as e:
            print(f"    Search error: {e}")

    print(f"  Collected {len(collected)} raw intelligence items")
    return "\n\n".join(
        f"[{i+1}] {r.get('title','—')} ({r.get('source','unknown')})\n{r.get('snippet','')}"
        for i, r in enumerate(collected)
    )


# ── GENERATE BULLETIN ─────────────────────────────────────────────────────────

def generate_bulletin(client: anthropic.Anthropic, raw_intel: str) -> dict:
    """Synthesise live search results into structured bulletin JSON."""
    print(f"[{datetime.now(SAST).strftime('%H:%M:%S')}] Generating bulletin...")

    system_prompt = f"""You are the iGuardSA Overwatch threat intelligence engine producing a daily OSINT bulletin.

TODAY: {TODAY}
FOCUS TOPICS: {FOCUS_TOPICS}
TIER 1 SOURCES: {', '.join(TIER1_SOURCES)}

You have been provided with LIVE WEB SEARCH RESULTS collected this morning. Use them as your primary source material.
Synthesise real findings into the bulletin. Mark findings derived from live search as "live": true.
Include 7-9 findings: ransomware, APT/nation-state, exploited CVEs, BEC/phishing, Africa-specific threats,
and at least one item relevant to Barloworld/Ingrain/Zahid/VT focus targets.
Be specific — real threat actor names, CVEs, malware families, TTPs.
Flag ANYTHING relevant to South Africa with sa_relevant: true and a written sa_reason.

Return ONLY valid JSON matching this schema exactly, no markdown, no backticks:
{BULLETIN_SCHEMA}

LIVE SEARCH RESULTS:
{raw_intel}"""

    response = client.messages.create(
        model="claude-sonnet-4-20250514",
        max_tokens=4000,
        system=system_prompt,
        messages=[{
            "role": "user",
            "content": f"Generate the daily OSINT bulletin for {TODAY}. Return only the JSON object."
        }]
    )

    raw = "".join(b.text for b in response.content if hasattr(b, "text"))
    raw = raw.replace("```json", "").replace("```", "").strip()

    # Extract JSON object
    start = raw.find("{")
    end = raw.rfind("}") + 1
    if start >= 0 and end > start:
        return json.loads(raw[start:end])
    raise ValueError(f"Could not parse bulletin JSON. Raw response:\n{raw[:500]}")


# ── HTML EMAIL ────────────────────────────────────────────────────────────────

SEV_COLORS = {
    "CRITICAL": ("#7f1d1d", "#fecaca", "#dc2626"),
    "HIGH":     ("#78350f", "#fef3c7", "#d97706"),
    "MEDIUM":   ("#1e3a5f", "#dbeafe", "#3b82f6"),
    "INFO":     ("#1f2937", "#f3f4f6", "#6b7280"),
}

TL_COLORS = {
    "HIGH":   "#dc2626",
    "MEDIUM": "#d97706",
    "LOW":    "#16a34a",
}

def sev_badge(sev: str) -> str:
    bg, _, border = SEV_COLORS.get(sev, SEV_COLORS["INFO"])
    return (
        f'<span style="display:inline-block;padding:2px 8px;border-radius:4px;'
        f'font-size:10px;font-weight:700;font-family:monospace;letter-spacing:.06em;'
        f'background:{bg};color:{border};border:1px solid {border}">{sev}</span>'
    )

def threat_bar(label: str, value: int, color: str) -> str:
    pct = max(0, min(100, value))
    return f"""
    <tr>
      <td style="font-size:12px;color:#9ca3af;padding:3px 0;width:120px">{label}</td>
      <td style="padding:3px 8px">
        <div style="background:#1f2937;border-radius:3px;height:6px;overflow:hidden">
          <div style="width:{pct}%;height:100%;background:{color};border-radius:3px"></div>
        </div>
      </td>
      <td style="font-size:11px;font-family:monospace;color:{color};width:36px;text-align:right">{pct}%</td>
    </tr>"""

def finding_card(f: dict, idx: int) -> str:
    sev = f.get("severity", "INFO")
    bg, light, border = SEV_COLORS.get(sev, SEV_COLORS["INFO"])
    live_tag = '<span style="display:inline-block;padding:1px 5px;border-radius:3px;font-size:9px;font-weight:700;font-family:monospace;background:#78350f;color:#fde68a;border:1px solid #d97706;margin-left:5px">LIVE</span>' if f.get("live") else ""
    za_tag = '<span style="display:inline-block;padding:1px 5px;border-radius:3px;font-size:9px;font-weight:700;font-family:monospace;background:#14532d;color:#86efac;border:1px solid #16a34a;margin-left:5px">ZA</span>' if f.get("sa_relevant") else ""

    ioc_html = ""
    if f.get("iocs"):
        ioc_items = "".join(
            f'<div style="font-family:monospace;font-size:11px;color:#f87171;padding:2px 0;border-bottom:1px solid #1f2937">{ioc}</div>'
            for ioc in f["iocs"]
        )
        ioc_html = f"""
        <div style="margin-top:8px;padding:8px 10px;background:#0a0c10;border-radius:4px;border:1px solid #1f2937">
          <div style="font-family:monospace;font-size:9px;color:#4b5563;text-transform:uppercase;letter-spacing:.08em;margin-bottom:5px">Indicators</div>
          {ioc_items}
        </div>"""

    sa_html = ""
    if f.get("sa_relevant") and f.get("sa_reason"):
        sa_html = f"""
        <div style="margin-top:8px;padding:8px 10px;background:#052e16;border-radius:4px;border-left:3px solid #16a34a">
          <span style="font-size:11px;color:#86efac"><strong style="color:#4ade80">SA relevance:</strong> {f['sa_reason']}</span>
        </div>"""

    tags_html = ""
    if f.get("tags"):
        tags = "".join(
            f'<span style="font-family:monospace;font-size:9px;padding:1px 6px;border-radius:3px;background:#1f2937;color:#6b7280;border:1px solid #374151;margin:1px 2px 1px 0;display:inline-block">{t}</span>'
            for t in f["tags"]
        )
        tags_html = f'<div style="margin-top:7px">{tags}</div>'

    return f"""
    <div style="border:1px solid #1f2937;border-radius:6px;margin-bottom:10px;overflow:hidden">
      <div style="display:flex;align-items:center;gap:8px;padding:8px 12px;background:#0f1218;border-bottom:1px solid #1f2937;flex-wrap:wrap">
        {sev_badge(sev)}
        <span style="font-size:12px;font-weight:600;color:#f3f4f6;flex:1">{f.get('title','')}{live_tag}{za_tag}</span>
        <span style="font-family:monospace;font-size:10px;color:#4b5563">{f.get('source','')}</span>
      </div>
      <div style="padding:10px 12px;font-size:12px;color:#9ca3af;line-height:1.7">
        {f.get('body','')}
        {sa_html}
        {ioc_html}
        {tags_html}
      </div>
    </div>"""

def ioc_row(ioc: dict) -> str:
    return f"""
    <tr style="border-bottom:1px solid #1f2937">
      <td style="padding:5px 8px;font-family:monospace;font-size:9px;color:#6b7280;background:#0f1218;white-space:nowrap">{ioc.get('type','')}</td>
      <td style="padding:5px 8px;font-family:monospace;font-size:11px;color:#f87171;max-width:220px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">{ioc.get('value','')}</td>
      <td style="padding:5px 8px;font-size:11px;color:#6b7280">{ioc.get('context','')}</td>
    </tr>"""

def src_row(s: dict) -> str:
    icons = {"ok": "✓", "limited": "~", "unavailable": "✗"}
    colors = {"ok": "#4ade80", "limited": "#fbbf24", "unavailable": "#f87171"}
    st = s.get("status", "ok")
    return f"""
    <tr style="border-bottom:1px solid #1f2937">
      <td style="padding:4px 8px;font-family:monospace;font-size:11px;color:{colors.get(st,'#9ca3af')}">{icons.get(st,'?')}</td>
      <td style="padding:4px 8px;font-size:11px;color:#9ca3af">{s.get('source','')}</td>
      <td style="padding:4px 8px;font-family:monospace;font-size:10px;color:#6b7280;text-align:right">{s.get('items_found',0)} items</td>
    </tr>"""

def render_html(data: dict) -> str:
    tl = data.get("overall_threat_level", "HIGH")
    tl_color = TL_COLORS.get(tl, "#d97706")
    tm = data.get("threat_levels", {})

    findings_html = "".join(
        finding_card(f, i) for i, f in enumerate(data.get("findings", []))
    )
    ioc_rows = "".join(ioc_row(i) for i in data.get("iocs", []))
    src_rows = "".join(src_row(s) for s in data.get("source_log", []))
    sector_tags = "".join(
        f'<span style="font-family:monospace;font-size:10px;padding:3px 10px;border-radius:3px;border:1px solid #374151;color:#9ca3af;margin:2px 3px 2px 0;display:inline-block">{s}</span>'
        for s in data.get("sectors_at_risk", [])
    )

    threat_bars = (
        threat_bar("Ransomware",     tm.get("ransomware", 0),     "#dc2626") +
        threat_bar("BEC / phishing", tm.get("bec_phishing", 0),   "#d97706") +
        threat_bar("State-sponsored",tm.get("state_sponsored", 0),"#818cf8") +
        threat_bar("Supply chain",   tm.get("supply_chain", 0),    "#22d3ee")
    )

    finding_count = len(data.get("findings", []))
    sa_count = sum(1 for f in data.get("findings", []) if f.get("sa_relevant"))
    live_count = sum(1 for f in data.get("findings", []) if f.get("live"))
    ioc_count = len(data.get("iocs", []))

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Overwatch Daily OSINT Bulletin — {TODAY_DISPLAY}</title>
</head>
<body style="margin:0;padding:0;background:#030507;font-family:'Segoe UI',Arial,sans-serif">

<div style="max-width:680px;margin:0 auto;background:#080b0f">

  <!-- HEADER -->
  <div style="background:#0a0c10;border-bottom:1px solid #1f2937;padding:14px 24px;display:flex;align-items:center;justify-content:space-between">
    <div>
      <div style="font-family:monospace;font-size:14px;font-weight:700;color:#00d4ff;letter-spacing:.08em">iGuardSA / OVERWATCH</div>
      <div style="font-family:monospace;font-size:10px;color:#374151;margin-top:2px;letter-spacing:.05em">DAILY OSINT BULLETIN · {TODAY_DISPLAY.upper()} · LIVE MODE</div>
    </div>
    <div style="text-align:right">
      <div style="font-family:monospace;font-size:10px;padding:3px 10px;border-radius:3px;background:#052e16;color:#4ade80;border:1px solid #166534">TLP:GREEN</div>
      <div style="font-family:monospace;font-size:10px;color:{tl_color};margin-top:4px;font-weight:700">{tl} THREAT</div>
    </div>
  </div>

  <!-- SUMMARY BANNER -->
  <div style="background:#0c0e13;border-bottom:1px solid #dc262620;border-left:4px solid {tl_color};padding:12px 20px">
    <div style="font-family:monospace;font-size:9px;color:#6b7280;text-transform:uppercase;letter-spacing:.1em;margin-bottom:6px">Executive summary</div>
    <div style="font-size:13px;color:#e5e7eb;line-height:1.7">{data.get('executive_summary','')}</div>
  </div>

  <!-- METRICS -->
  <div style="display:grid;background:#0a0c10;border-bottom:1px solid #1f2937;padding:0">
    <table width="100%" cellpadding="0" cellspacing="0">
      <tr>
        <td style="padding:12px 16px;text-align:center;border-right:1px solid #1f2937">
          <div style="font-family:monospace;font-size:9px;color:#4b5563;text-transform:uppercase;letter-spacing:.08em;margin-bottom:3px">Findings</div>
          <div style="font-size:22px;font-weight:700;color:#f3f4f6">{finding_count}</div>
        </td>
        <td style="padding:12px 16px;text-align:center;border-right:1px solid #1f2937">
          <div style="font-family:monospace;font-size:9px;color:#4b5563;text-transform:uppercase;letter-spacing:.08em;margin-bottom:3px">SA relevant</div>
          <div style="font-size:22px;font-weight:700;color:#4ade80">{sa_count}</div>
        </td>
        <td style="padding:12px 16px;text-align:center;border-right:1px solid #1f2937">
          <div style="font-family:monospace;font-size:9px;color:#4b5563;text-transform:uppercase;letter-spacing:.08em;margin-bottom:3px">Live sourced</div>
          <div style="font-size:22px;font-weight:700;color:#fbbf24">{live_count}</div>
        </td>
        <td style="padding:12px 16px;text-align:center">
          <div style="font-family:monospace;font-size:9px;color:#4b5563;text-transform:uppercase;letter-spacing:.08em;margin-bottom:3px">IOCs</div>
          <div style="font-size:22px;font-weight:700;color:#f87171">{ioc_count}</div>
        </td>
      </tr>
    </table>
  </div>

  <div style="padding:16px 20px">

    <!-- THREAT LEVELS -->
    <div style="font-family:monospace;font-size:9px;color:#4b5563;text-transform:uppercase;letter-spacing:.1em;margin-bottom:8px;padding-bottom:5px;border-bottom:1px solid #1f2937">Threat levels — Africa region</div>
    <table width="100%" cellpadding="0" cellspacing="0" style="margin-bottom:16px">
      {threat_bars}
    </table>

    <!-- SECTORS -->
    <div style="font-family:monospace;font-size:9px;color:#4b5563;text-transform:uppercase;letter-spacing:.1em;margin-bottom:8px;padding-bottom:5px;border-bottom:1px solid #1f2937">Sectors at risk</div>
    <div style="margin-bottom:16px">{sector_tags}</div>

    <!-- FINDINGS -->
    <div style="font-family:monospace;font-size:9px;color:#4b5563;text-transform:uppercase;letter-spacing:.1em;margin-bottom:10px;padding-bottom:5px;border-bottom:1px solid #1f2937">Findings</div>
    {findings_html}

    <!-- IOC TABLE -->
    <div style="font-family:monospace;font-size:9px;color:#4b5563;text-transform:uppercase;letter-spacing:.1em;margin:16px 0 8px;padding-bottom:5px;border-bottom:1px solid #1f2937">IOC quick reference</div>
    <table width="100%" cellpadding="0" cellspacing="0" style="background:#0a0c10;border:1px solid #1f2937;border-radius:5px;margin-bottom:16px;overflow:hidden">
      <thead>
        <tr style="background:#0f1218;border-bottom:1px solid #1f2937">
          <th style="font-family:monospace;font-size:9px;color:#4b5563;text-transform:uppercase;padding:6px 8px;text-align:left;letter-spacing:.06em">Type</th>
          <th style="font-family:monospace;font-size:9px;color:#4b5563;text-transform:uppercase;padding:6px 8px;text-align:left;letter-spacing:.06em">Value</th>
          <th style="font-family:monospace;font-size:9px;color:#4b5563;text-transform:uppercase;padding:6px 8px;text-align:left;letter-spacing:.06em">Context</th>
        </tr>
      </thead>
      <tbody>{ioc_rows}</tbody>
    </table>

    <!-- SOURCE LOG -->
    <div style="font-family:monospace;font-size:9px;color:#4b5563;text-transform:uppercase;letter-spacing:.1em;margin-bottom:8px;padding-bottom:5px;border-bottom:1px solid #1f2937">Source log</div>
    <table width="100%" cellpadding="0" cellspacing="0" style="background:#0a0c10;border:1px solid #1f2937;border-radius:5px;margin-bottom:20px;overflow:hidden">
      <tbody>{src_rows}</tbody>
    </table>

  </div>

  <!-- FOOTER -->
  <div style="background:#0a0c10;border-top:1px solid #1f2937;padding:12px 24px;text-align:center">
    <div style="font-family:monospace;font-size:10px;color:#374151">
      Generated by iGuardSA Overwatch Intelligence Engine · {TODAY_DISPLAY}
    </div>
    <div style="font-family:monospace;font-size:10px;color:#374151;margin-top:3px">
      TLP:GREEN — May be shared within the organisation and with trusted partner organisations
    </div>
  </div>

</div>
</body>
</html>"""


# ── SEND EMAIL ────────────────────────────────────────────────────────────────

def send_email(html_body: str, data: dict) -> None:
    tl = data.get("overall_threat_level", "HIGH")
    finding_count = len(data.get("findings", []))
    sa_count = sum(1 for f in data.get("findings", []) if f.get("sa_relevant"))

    subject = (
        f"[OVERWATCH] Daily OSINT Brief — {TODAY_DISPLAY} "
        f"| {tl} | {finding_count} findings | {sa_count} SA"
    )

    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"] = f"Overwatch Intelligence <{SENDER_EMAIL}>"
    msg["To"] = RECIPIENT_EMAIL

    # Plain text fallback
    plain = f"OVERWATCH DAILY OSINT BULLETIN — {TODAY_DISPLAY}\n"
    plain += f"Threat level: {tl} | Findings: {finding_count} | SA relevant: {sa_count}\n\n"
    plain += f"Executive summary:\n{data.get('executive_summary','')}\n\n"
    for f in data.get("findings", []):
        plain += f"[{f.get('severity','?')}] {f.get('title','')}\n"
        plain += f"Source: {f.get('source','')}\n"
        plain += f"{f.get('body','')}\n"
        if f.get("sa_relevant"):
            plain += f"SA: {f.get('sa_reason','')}\n"
        plain += "\n"
    plain += f"\nTLP:GREEN — iGuardSA Overwatch Intelligence\n"

    msg.attach(MIMEText(plain, "plain"))
    msg.attach(MIMEText(html_body, "html"))

    print(f"[{datetime.now(SAST).strftime('%H:%M:%S')}] Sending email to {RECIPIENT_EMAIL}...")
    with smtplib.SMTP_SSL("smtp.gmail.com", 465) as server:
        server.login(SENDER_EMAIL, GMAIL_APP_PWD)
        server.sendmail(SENDER_EMAIL, RECIPIENT_EMAIL, msg.as_string())
    print(f"[{datetime.now(SAST).strftime('%H:%M:%S')}] Email sent successfully.")


# ── MAIN ──────────────────────────────────────────────────────────────────────

def main():
    print(f"\n{'='*60}")
    print(f"  OVERWATCH DAILY OSINT BULLETIN")
    print(f"  {TODAY_DISPLAY}")
    print(f"{'='*60}\n")

    client = anthropic.Anthropic(api_key=ANTHROPIC_KEY)

    # 1. Live searches
    raw_intel = run_live_searches(client)

    # 2. Generate bulletin
    data = generate_bulletin(client, raw_intel)
    print(f"[{datetime.now(SAST).strftime('%H:%M:%S')}] Bulletin generated — "
          f"{len(data.get('findings',[]))} findings, "
          f"threat level: {data.get('overall_threat_level','?')}")

    # 3. Save JSON (artifact)
    json_path = Path(f"bulletin_{TODAY}.json")
    json_path.write_text(json.dumps(data, indent=2))
    print(f"[{datetime.now(SAST).strftime('%H:%M:%S')}] JSON saved: {json_path}")

    # 4. Render HTML
    html = render_html(data)

    # 5. Save HTML (artifact)
    html_path = Path(f"bulletin_{TODAY}.html")
    html_path.write_text(html)
    print(f"[{datetime.now(SAST).strftime('%H:%M:%S')}] HTML saved: {html_path}")

    # 6. Send email
    send_email(html, data)

    print(f"\n{'='*60}")
    print(f"  COMPLETE — {TODAY_DISPLAY}")
    print(f"{'='*60}\n")


if __name__ == "__main__":
    main()
