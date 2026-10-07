"""Oracle Alert Log Analyzer.

Parses an Oracle alert log, groups ORA- errors into incidents, classifies them
by type and severity, and produces:
  - a summary in the terminal
  - a CSV with every incident
  - an HTML dashboard (top errors with first/last seen, charts, latest incidents)

Usage:
    python oracle_log_parser.py path/to/alert.log
    python oracle_log_parser.py alert.log --csv out.csv --html out.html --top 10 --max-rows 500
"""

import argparse
import csv
import html
import json
import re
import sys
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

# ---------------------------------------------------------------------------
# Classification
# ---------------------------------------------------------------------------

# Known Oracle errors. Error numbers don't follow neat ranges in Oracle,
# so known codes are looked up directly. Add to this as you meet new ones.
KNOWN_ERRORS = {
    # Critical: instance crash, hang, corruption, or out of recovery space
    "ORA-00600": ("Internal error", "Critical"),
    "ORA-07445": ("Internal error (OS exception)", "Critical"),
    "ORA-00257": ("Archiver stuck", "Critical"),
    "ORA-16038": ("Log cannot be archived", "Critical"),
    "ORA-19809": ("Recovery area full", "Critical"),
    "ORA-01578": ("Data block corrupted", "Critical"),
    "ORA-04031": ("Shared memory exhausted", "Critical"),
    "ORA-00470": ("LGWR process terminated", "Critical"),
    "ORA-00471": ("DBWR process terminated", "Critical"),
    "ORA-00474": ("SMON process terminated", "Critical"),
    "ORA-27072": ("File I/O error", "Critical"),
    "ORA-00353": ("Redo log corruption", "Critical"),
    "ORA-00312": ("Online redo log problem", "Critical"),
    # High: service impact likely if not handled soon
    "ORA-01653": ("Unable to extend table", "High"),
    "ORA-01654": ("Unable to extend index", "High"),
    "ORA-01652": ("Unable to extend temp segment", "High"),
    "ORA-01688": ("Unable to extend table partition", "High"),
    "ORA-01691": ("Unable to extend LOB segment", "High"),
    "ORA-30036": ("Unable to extend undo segment", "High"),
    "ORA-01555": ("Snapshot too old (undo)", "High"),
    "ORA-04030": ("Process memory exhausted", "High"),
    "ORA-00020": ("Maximum processes exceeded", "High"),
    "ORA-00018": ("Maximum sessions exceeded", "High"),
    "ORA-01113": ("Datafile needs media recovery", "High"),
    "ORA-01157": ("Cannot identify datafile", "High"),
    "ORA-12537": ("Listener connection closed", "High"),
    # Medium: application or concurrency issues
    "ORA-00060": ("Deadlock detected", "Medium"),
    "ORA-01013": ("User cancelled operation", "Low"),
    "ORA-03113": ("End-of-file on communication channel", "Medium"),
    "ORA-12170": ("Connect timeout", "Medium"),
    # Context codes: these explain another error rather than being one
    "ORA-06512": ("Error stack location (context)", "Low"),
    "ORA-01110": ("Datafile name (context)", "Low"),
    "ORA-19804": ("Cannot reclaim recovery space (context)", "Low"),
    "ORA-27037": ("Unable to get file status (context)", "Low"),
}

SEVERITY_ORDER = ["Critical", "High", "Medium", "Low"]


def normalize_code(raw_number: str) -> str:
    """Oracle writes both ORA-1653 and ORA-01653. Normalize to 5 digits."""
    return f"ORA-{int(raw_number):05d}"


def classify(code: str) -> tuple[str, str]:
    """Return (type, severity) for a normalized ORA- code."""
    if code in KNOWN_ERRORS:
        return KNOWN_ERRORS[code]
    number = int(code[4:])
    # Broad fallbacks for codes not in the lookup table
    if 1650 <= number <= 1699:
        return ("Space allocation problem", "High")
    if 12100 <= number <= 12699:
        return ("Oracle Net connectivity", "Medium")
    if 27000 <= number <= 27399:
        return ("Operating system / I/O", "High")
    return ("Unclassified", "Medium")


# ---------------------------------------------------------------------------
# Parsing
# ---------------------------------------------------------------------------

# 12c+ format: 2026-10-05T02:14:33.456789-04:00 (offset can be + or -)
ISO_TS = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?[+-]\d{2}:\d{2}$")
# 11g and older format: Mon Oct 05 02:14:33 2026
LEGACY_TS = re.compile(r"^[A-Z][a-z]{2} [A-Z][a-z]{2} [ \d]\d \d{2}:\d{2}:\d{2} \d{4}$")
ORA_CODE = re.compile(r"ORA-(\d{3,5})\b")


def parse_timestamp(line: str):
    """Return a datetime if the line is an alert log timestamp, else None."""
    if ISO_TS.match(line):
        # Convert to UTC and drop the offset so every timestamp is comparable,
        # even in logs that mix the new and legacy formats after an upgrade.
        return datetime.fromisoformat(line).astimezone(timezone.utc).replace(tzinfo=None)
    if LEGACY_TS.match(line):
        return datetime.strptime(" ".join(line.split()), "%a %b %d %H:%M:%S %Y")
    return None


@dataclass
class Incident:
    timestamp: datetime | None
    timestamp_text: str
    code: str
    error_type: str
    severity: str
    line: str
    related: list[str] = field(default_factory=list)


def parse_log(log_path: Path) -> list[Incident]:
    """Group ORA- errors into incidents.

    The first ORA- code after each timestamp is the incident. Further codes in
    the same block (error stacks such as ORA-06512 or ORA-01110) are attached
    to it as related codes instead of being counted as separate errors.
    """
    incidents: list[Incident] = []
    current_ts = None
    current_ts_text = "Unknown"
    block_incident: Incident | None = None

    with open(log_path, "r", encoding="utf-8", errors="replace") as f:
        for raw in f:
            line = raw.strip()
            if not line:
                continue

            ts = parse_timestamp(line)
            if ts is not None:
                current_ts, current_ts_text = ts, line
                block_incident = None  # new block starts
                continue

            codes = [normalize_code(n) for n in ORA_CODE.findall(line)]
            if not codes:
                continue

            if block_incident is None:
                primary, extra = codes[0], codes[1:]
                err_type, severity = classify(primary)
                block_incident = Incident(current_ts, current_ts_text, primary,
                                          err_type, severity, line, list(extra))
                incidents.append(block_incident)
            else:
                for code in codes:
                    if code != block_incident.code and code not in block_incident.related:
                        block_incident.related.append(code)

    return incidents


# ---------------------------------------------------------------------------
# Summaries
# ---------------------------------------------------------------------------

def top_errors(incidents: list[Incident], n: int) -> list[dict]:
    """Top N error codes with count and first/last seen."""
    stats: dict[str, dict] = {}
    for inc in incidents:
        s = stats.setdefault(inc.code, {
            "code": inc.code, "type": inc.error_type, "severity": inc.severity,
            "count": 0, "first": None, "last": None,
            "first_text": inc.timestamp_text, "last_text": inc.timestamp_text,
        })
        s["count"] += 1
        if inc.timestamp is not None:
            if s["first"] is None or inc.timestamp < s["first"]:
                s["first"], s["first_text"] = inc.timestamp, inc.timestamp_text
            if s["last"] is None or inc.timestamp > s["last"]:
                s["last"], s["last_text"] = inc.timestamp, inc.timestamp_text
    ranked = sorted(stats.values(),
                    key=lambda s: (-s["count"], SEVERITY_ORDER.index(s["severity"])))
    return ranked[:n]


def print_summary(incidents: list[Incident], top: list[dict], log_path: Path) -> None:
    sev = Counter(i.severity for i in incidents)
    print(f"\nAlert log: {log_path}")
    print(f"Incidents: {len(incidents)}  |  " +
          "  ".join(f"{s}: {sev.get(s, 0)}" for s in SEVERITY_ORDER))
    print(f"\n{'CODE':<10} {'COUNT':>6}  {'SEVERITY':<9} {'TYPE':<34} {'FIRST SEEN':<33} LAST SEEN")
    print("-" * 128)
    for t in top:
        print(f"{t['code']:<10} {t['count']:>6}  {t['severity']:<9} {t['type'][:34]:<34} "
              f"{t['first_text']:<33} {t['last_text']}")


def write_csv(incidents: list[Incident], csv_path: Path) -> None:
    with open(csv_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["Timestamp", "Error Code", "Severity", "Type", "Related Codes", "Error Line"])
        for i in incidents:
            writer.writerow([i.timestamp_text, i.code, i.severity, i.error_type,
                             " ".join(i.related), i.line])


# ---------------------------------------------------------------------------
# HTML dashboard
# ---------------------------------------------------------------------------

def _json_for_script(value) -> str:
    """JSON that is safe to place inside a <script> tag."""
    return json.dumps(value).replace("</", "<\\/")


def write_html(incidents: list[Incident], top: list[dict], log_path: Path,
               html_path: Path, max_rows: int) -> None:
    e = html.escape
    sev = Counter(i.severity for i in incidents)
    latest = sorted(incidents, key=lambda i: (i.timestamp is None, i.timestamp or datetime.min),
                    reverse=True)[:max_rows]
    generated = datetime.now().strftime("%Y-%m-%d %H:%M")

    top_rows = "".join(
        f"<tr><td class='code'>{e(t['code'])}</td><td class='num'>{t['count']}</td>"
        f"<td><span class='badge {t['severity'].lower()}'>{t['severity']}</span></td>"
        f"<td>{e(t['type'])}</td><td>{e(t['first_text'])}</td><td>{e(t['last_text'])}</td></tr>"
        for t in top)

    incident_rows = "".join(
        f"<tr><td>{e(i.timestamp_text)}</td><td class='code'>{e(i.code)}</td>"
        f"<td><span class='badge {i.severity.lower()}'>{i.severity}</span></td>"
        f"<td>{e(i.error_type)}</td><td class='code'>{e(' '.join(i.related))}</td>"
        f"<td class='msg' title='{e(i.line, quote=True)}'>{e(i.line)}</td></tr>"
        for i in latest)

    shown_note = (f"Showing the latest {len(latest)} of {len(incidents)} incidents. "
                  f"The full list is in the CSV.") if len(incidents) > len(latest) else \
                 f"Showing all {len(incidents)} incidents."

    bar_labels = [t["code"] for t in top]
    bar_values = [t["count"] for t in top]
    bar_colors = [{"Critical": "#c0392b", "High": "#d35400", "Medium": "#b7950b", "Low": "#27ae60"}[t["severity"]]
                  for t in top]
    sev_values = [sev.get(s, 0) for s in SEVERITY_ORDER]

    page = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Oracle Alert Log Dashboard</title>
<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.1/dist/chart.umd.min.js"></script>
<style>
  :root {{ --bg:#f3f5f7; --card:#fff; --ink:#1d2731; --muted:#5d6b78; --line:#dde3e8;
          --critical:#c0392b; --high:#d35400; --medium:#b7950b; --low:#27ae60; }}
  * {{ box-sizing:border-box; }}
  body {{ margin:0; background:var(--bg); color:var(--ink);
         font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif; }}
  .wrap {{ max-width:1300px; margin:0 auto; padding:24px 20px 40px; }}
  h1 {{ margin:0 0 4px; font-size:26px; }}
  h2 {{ margin:0 0 12px; font-size:18px; }}
  .sub {{ color:var(--muted); margin:0; font-size:14px; word-break:break-all; }}
  .kpis {{ display:grid; grid-template-columns:repeat(auto-fit,minmax(180px,1fr)); gap:14px; margin:20px 0; }}
  .card {{ background:var(--card); border:1px solid var(--line); border-radius:6px; padding:16px; }}
  .kpi {{ border-top:4px solid var(--muted); }}
  .kpi.critical {{ border-top-color:var(--critical); }} .kpi.high {{ border-top-color:var(--high); }}
  .kpi.medium {{ border-top-color:var(--medium); }} .kpi.low {{ border-top-color:var(--low); }}
  .kpi .label {{ font-size:14px; color:var(--muted); }}
  .kpi .value {{ font-size:30px; font-weight:700; margin-top:4px; }}
  .grid {{ display:grid; grid-template-columns:1fr; gap:14px; margin-bottom:14px; }}
  @media (min-width:960px) {{ .grid {{ grid-template-columns:2fr 1fr; }} }}
  .chart {{ position:relative; height:300px; }}
  .scroll {{ overflow:auto; max-height:520px; }}
  table {{ width:100%; border-collapse:collapse; font-size:14px; }}
  th, td {{ text-align:left; padding:9px 10px; border-bottom:1px solid var(--line); vertical-align:top; }}
  th {{ position:sticky; top:0; background:#f8fafb; font-weight:600; }}
  td.code {{ font-family:ui-monospace,Menlo,Consolas,monospace; white-space:nowrap; }}
  td.num {{ text-align:right; font-variant-numeric:tabular-nums; }}
  td.msg {{ max-width:420px; overflow:hidden; text-overflow:ellipsis; white-space:nowrap; }}
  .badge {{ display:inline-block; padding:2px 8px; border-radius:3px; font-size:12px; font-weight:600; color:#fff; }}
  .badge.critical {{ background:var(--critical); }} .badge.high {{ background:var(--high); }}
  .badge.medium {{ background:var(--medium); }} .badge.low {{ background:var(--low); }}
  .note {{ color:var(--muted); font-size:13px; margin:0 0 10px; }}
</style>
</head>
<body>
<div class="wrap">
  <h1>Oracle Alert Log Dashboard</h1>
  <p class="sub">Log: {e(str(log_path))} &nbsp;|&nbsp; Generated: {generated}</p>

  <div class="kpis">
    <div class="card kpi"><div class="label">Incidents</div><div class="value">{len(incidents)}</div></div>
    <div class="card kpi critical"><div class="label">Critical</div><div class="value">{sev.get('Critical', 0)}</div></div>
    <div class="card kpi high"><div class="label">High</div><div class="value">{sev.get('High', 0)}</div></div>
    <div class="card kpi medium"><div class="label">Medium</div><div class="value">{sev.get('Medium', 0)}</div></div>
    <div class="card kpi low"><div class="label">Low</div><div class="value">{sev.get('Low', 0)}</div></div>
  </div>

  <div class="card" style="margin-bottom:14px">
    <h2>Top {len(top)} errors</h2>
    <div class="scroll"><table>
      <thead><tr><th>Code</th><th>Count</th><th>Severity</th><th>Type</th><th>First seen</th><th>Last seen</th></tr></thead>
      <tbody>{top_rows}</tbody>
    </table></div>
  </div>

  <div class="grid">
    <div class="card"><h2>Incidents by error code</h2><div class="chart"><canvas id="bar"></canvas></div></div>
    <div class="card"><h2>Incidents by severity</h2><div class="chart"><canvas id="pie"></canvas></div></div>
  </div>

  <div class="card">
    <h2>Latest incidents</h2>
    <p class="note">{shown_note}</p>
    <div class="scroll"><table>
      <thead><tr><th>Timestamp</th><th>Code</th><th>Severity</th><th>Type</th><th>Related</th><th>Message</th></tr></thead>
      <tbody>{incident_rows}</tbody>
    </table></div>
  </div>
</div>
<script>
  if (window.Chart) {{
    new Chart(document.getElementById("bar"), {{
      type: "bar",
      data: {{ labels: {_json_for_script(bar_labels)},
               datasets: [{{ data: {_json_for_script(bar_values)}, backgroundColor: {_json_for_script(bar_colors)}, borderRadius: 3 }}] }},
      options: {{ responsive: true, maintainAspectRatio: false, plugins: {{ legend: {{ display: false }} }},
                  scales: {{ y: {{ beginAtZero: true }}, x: {{ grid: {{ display: false }} }} }} }}
    }});
    new Chart(document.getElementById("pie"), {{
      type: "doughnut",
      data: {{ labels: {_json_for_script(SEVERITY_ORDER)},
               datasets: [{{ data: {_json_for_script(sev_values)},
                             backgroundColor: ["#c0392b", "#d35400", "#b7950b", "#27ae60"] }}] }},
      options: {{ responsive: true, maintainAspectRatio: false, plugins: {{ legend: {{ position: "bottom" }} }} }}
    }});
  }}
</script>
</body>
</html>
"""
    html_path.write_text(page, encoding="utf-8")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="Analyze ORA- errors in an Oracle alert log.")
    p.add_argument("alert_log", type=Path, help="Path to the alert log file")
    p.add_argument("--csv", type=Path, default=Path("oracle_errors.csv"), help="CSV output path")
    p.add_argument("--html", type=Path, default=Path("oracle_dashboard.html"), help="HTML dashboard path")
    p.add_argument("--top", type=int, default=10, help="Number of top errors to show (default 10)")
    p.add_argument("--max-rows", type=int, default=500,
                   help="Latest incidents to show in the dashboard table (default 500)")
    return p


def main(argv=None) -> int:
    args = build_arg_parser().parse_args(argv)
    if not args.alert_log.is_file():
        print(f"Error: file not found: {args.alert_log}", file=sys.stderr)
        return 1

    incidents = parse_log(args.alert_log)
    top = top_errors(incidents, args.top)

    print_summary(incidents, top, args.alert_log)
    write_csv(incidents, args.csv)
    write_html(incidents, top, args.alert_log, args.html, args.max_rows)
    print(f"\nCSV:       {args.csv}")
    print(f"Dashboard: {args.html}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
