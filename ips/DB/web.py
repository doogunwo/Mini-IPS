#!/usr/bin/env python3
import argparse
import html
import json
import pathlib
import sqlite3
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Optional
from urllib.parse import parse_qs, urlparse


def db_connect(db_file: pathlib.Path) -> sqlite3.Connection:
    conn = sqlite3.connect(db_file)
    conn.row_factory = sqlite3.Row
    return conn


def fetch_summary(conn: sqlite3.Connection) -> dict[str, int]:
    rows = conn.execute(
        """
        SELECT COALESCE(event, 'unknown') AS event_name, COUNT(*) AS cnt
        FROM ips_events
        GROUP BY COALESCE(event, 'unknown')
        ORDER BY cnt DESC
        """
    ).fetchall()
    return {row["event_name"]: row["cnt"] for row in rows}


def fetch_overview(conn: sqlite3.Connection) -> dict[str, object]:
    total = conn.execute("SELECT COUNT(*) AS cnt FROM ips_events").fetchone()["cnt"]
    latest = conn.execute("SELECT MAX(ts) AS ts FROM ips_events").fetchone()["ts"]
    detect = conn.execute(
        "SELECT COUNT(*) AS cnt FROM ips_events WHERE event = 'detect'"
    ).fetchone()["cnt"]
    rst = conn.execute(
        "SELECT COUNT(*) AS cnt FROM ips_events WHERE event = 'rst_request'"
    ).fetchone()["cnt"]
    errors = conn.execute(
        "SELECT COUNT(*) AS cnt FROM ips_events WHERE level = 'ERROR'"
    ).fetchone()["cnt"]
    top_attack_row = conn.execute(
        """
        SELECT attack, COUNT(*) AS cnt
        FROM ips_events
        WHERE attack IS NOT NULL AND attack <> ''
        GROUP BY attack
        ORDER BY cnt DESC, attack ASC
        LIMIT 1
        """
    ).fetchone()
    return {
        "total": total,
        "latest": latest,
        "detect": detect,
        "rst": rst,
        "errors": errors,
        "top_attack": top_attack_row["attack"] if top_attack_row else None,
        "top_attack_count": top_attack_row["cnt"] if top_attack_row else 0,
    }


def fetch_events(conn: sqlite3.Connection, event: Optional[str], q: Optional[str], limit: int):
    clauses = []
    params = []

    if event:
        clauses.append("event = ?")
        params.append(event)

    if q:
        clauses.append(
            "("
            "COALESCE(attack, '') LIKE ? OR "
            "COALESCE(src_ip, '') LIKE ? OR "
            "COALESCE(dst_ip, '') LIKE ? OR "
            "COALESCE(detail, '') LIKE ? OR "
            "COALESCE(matched, '') LIKE ? OR "
            "COALESCE(matched_texts, '') LIKE ? OR "
            "COALESCE(raw_line, '') LIKE ?"
            ")"
        )
        like = f"%{q}%"
        params.extend([like, like, like, like, like, like, like])

    where_sql = ""
    if clauses:
        where_sql = "WHERE " + " AND ".join(clauses)

    params.append(limit)
    return conn.execute(
        f"""
        SELECT id, ts, level, event, action_name, attack, where_name, src_ip, src_port,
               dst_ip, dst_port, score, threshold, match_count, matched, matched_texts,
               detect_us,
               detect_ms, detail, raw_line
        FROM ips_events
        {where_sql}
        ORDER BY id DESC
        LIMIT ?
        """,
        params,
    ).fetchall()


def event_tone(event: str, level: str) -> str:
    if event == "detect":
        return "threat"
    if event == "rst_request":
        return "block"
    if level == "ERROR" or "error" in (event or ""):
        return "error"
    return "info"


def format_timestamp_parts(ts: Optional[str]) -> tuple[str, str]:
    if not ts:
        return "-", "-"
    ts = ts.strip()
    if "T" not in ts:
        return ts, "-"
    date_part, time_part = ts.split("T", 1)
    if time_part.endswith("Z"):
        time_part = time_part[:-1]
    return date_part, time_part


def split_serialized(value: Optional[str]) -> list[str]:
    if not value:
        return []
    return [item.strip() for item in value.split("; ") if item.strip()]


def parse_rule_entry(entry: str) -> tuple[str, str]:
    parts = entry.split("|", 2)
    if len(parts) == 3:
        return parts[0], parts[2]
    if len(parts) == 2:
        return parts[0], parts[1]
    return "-", entry


def parse_text_entry(entry: str) -> tuple[str, str]:
    parts = entry.split("|", 1)
    if len(parts) == 2:
        return parts[0], parts[1]
    return "-", entry


def render_detail_html(row: sqlite3.Row) -> str:
    event = row["event"] or ""
    if event == "rst_request":
        return "<span class='muted-cell'>-</span>"

    if event == "detect":
        rules = split_serialized(row["matched"])
        texts = split_serialized(row["matched_texts"])
        lines = []
        max_len = max(len(rules), len(texts))
        for idx in range(max_len):
            rule_ctx, regex = parse_rule_entry(rules[idx]) if idx < len(rules) else ("-", "-")
            text_ctx, matched_text = parse_text_entry(texts[idx]) if idx < len(texts) else (rule_ctx, "-")
            context = text_ctx if text_ctx != "-" else rule_ctx
            lines.append(
                "<div class='detail-line'>"
                f"<div><span class='detail-label'>{html.escape(context)}</span></div>"
                f"<div><span class='detail-key'>regex</span>=<code>{html.escape(regex)}</code></div>"
                f"<div><span class='detail-key'>match</span>=<code>{html.escape(matched_text)}</code></div>"
                "</div>"
            )
        if lines:
            return f"<div class='detail-stack'>{''.join(lines)}</div>"

    detail = row["detail"] or row["raw_line"] or row["matched_texts"] or row["matched"] or ""
    if not detail:
        return "<span class='muted-cell'>-</span>"
    return f"<code>{html.escape(detail)}</code>"


def render_page(overview, summary, rows, selected_event: Optional[str], query: Optional[str], limit: int) -> bytes:
    table_rows = []
    for row in rows:
        tone = event_tone(row["event"] or "", row["level"] or "")
        date_part, time_part = format_timestamp_parts(row["ts"])
        is_rst = (row["event"] or "") == "rst_request"
        attack = "" if is_rst else (row["attack"] or "-")
        where_name = row["where_name"] or "-"
        source = f"{row['src_ip'] or '-'}:{row['src_port'] or '-'}"
        dest = f"{row['dst_ip'] or '-'}:{row['dst_port'] or '-'}"
        score_line = f"score={row['score'] or '-'} threshold={row['threshold'] or '-'} matches={row['match_count'] or '-'}"
        detect_us = row["detect_us"]
        detect_ms = row["detect_ms"]
        if detect_us is not None:
            detect_display = f"{detect_us / 1000.0:.3f}"
        elif detect_ms is not None:
            detect_display = str(detect_ms)
        else:
            detect_display = "-"
        detail_html = render_detail_html(row)
        table_rows.append(
            f"<tr class='tone-{tone}'>"
            f"<td class='mono'>{html.escape(str(row['id']))}</td>"
            f"<td><div class='ts-date'>{html.escape(date_part)}</div><div class='ts-time mono'>{html.escape(time_part)}</div><div class='sub'>{html.escape(where_name)}</div></td>"
            f"<td><span class='pill level-{html.escape((row['level'] or 'INFO').lower())}'>{html.escape(row['level'] or '')}</span></td>"
            f"<td><span class='pill event-{html.escape(tone)}'>{html.escape(row['event'] or '')}</span></td>"
            f"<td><strong>{html.escape(attack or '-')}</strong><div class='sub'>{html.escape(score_line)}</div></td>"
            f"<td class='mono'>{html.escape(source)}</td>"
            f"<td class='mono'>{html.escape(dest)}</td>"
            f"<td class='mono'>{html.escape(detect_display)}</td>"
            f"<td>{detail_html}</td>"
            "</tr>"
        )

    active = html.escape(selected_event or "all")
    search_value = html.escape(query or "")
    body = f"""<!doctype html>
<html lang="ko">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta http-equiv="refresh" content="15">
  <title>IPS Security Console</title>
  <style>
    :root {{
      --bg: #f3efe6;
      --paper: #fffdf7;
      --panel: #fbf7ef;
      --line: #d6c7ae;
      --ink: #171411;
      --muted: #6f6559;
      --threat: #8f2417;
      --block: #996c14;
      --error: #7f1d1d;
      --info: #29546b;
      --accent: #123d54;
      --shadow: 0 18px 45px rgba(56, 39, 20, 0.08);
    }}
    * {{ box-sizing: border-box; }}
    body {{ margin: 0; font-family: Georgia, serif; color: var(--ink); font-size: 9pt; background:
      radial-gradient(circle at top left, rgba(18,61,84,0.12), transparent 30%),
      radial-gradient(circle at top right, rgba(143,36,23,0.12), transparent 25%),
      linear-gradient(180deg, #eee5d3, var(--bg)); }}
    main {{ max-width: 1280px; margin: 0 auto; padding: 28px 18px 46px; }}
    .toolbar {{ display: block; margin-bottom: 18px; }}
    .panel {{ background: var(--paper); border: 1px solid var(--line); border-radius: 22px; padding: 18px; box-shadow: var(--shadow); }}
    .panel h2 {{ margin: 0 0 12px; font-size: 20px; }}
    form {{ display: grid; grid-template-columns: 1fr 180px 110px 90px; gap: 10px; }}
    input, select, button, a.button {{ width: 100%; padding: 12px 14px; border-radius: 14px; border: 1px solid var(--line); font: inherit; background: #fff; color: var(--ink); text-decoration: none; }}
    button {{ background: var(--accent); color: #fff; border-color: var(--accent); cursor: pointer; }}
    a.button {{ display: inline-flex; align-items: center; justify-content: center; }}
    .table-wrap {{ overflow: auto; }}
    table {{ width: 100%; border-collapse: collapse; min-width: 980px; }}
    th, td {{ padding: 12px 10px; border-bottom: 1px solid var(--line); text-align: left; vertical-align: top; font-size: 9pt; }}
    th {{ position: sticky; top: 0; background: #efe3cf; z-index: 1; }}
    .mono {{ font-family: "SFMono-Regular", Menlo, monospace; }}
    .ts-date {{ font-weight: 700; }}
    .ts-time {{ margin-top: 4px; }}
    .sub {{ margin-top: 6px; color: var(--muted); font-size: 12px; }}
    .muted-cell {{ color: var(--muted); }}
    .pill {{ display: inline-block; border-radius: 999px; padding: 6px 10px; font-size: 12px; font-weight: 700; letter-spacing: 0.03em; }}
    .level-warn {{ background: rgba(153,108,20,0.12); color: var(--block); }}
    .level-error {{ background: rgba(127,29,29,0.12); color: var(--error); }}
    .level-info {{ background: rgba(41,84,107,0.12); color: var(--info); }}
    .event-threat {{ background: rgba(143,36,23,0.12); color: var(--threat); }}
    .event-block {{ background: rgba(153,108,20,0.12); color: var(--block); }}
    .event-error {{ background: rgba(127,29,29,0.12); color: var(--error); }}
    .event-info {{ background: rgba(41,84,107,0.12); color: var(--info); }}
    .tone-threat td:first-child, .tone-block td:first-child, .tone-error td:first-child {{ border-left: 5px solid transparent; }}
    .tone-threat td:first-child {{ border-left-color: var(--threat); }}
    .tone-block td:first-child {{ border-left-color: var(--block); }}
    .tone-error td:first-child {{ border-left-color: var(--error); }}
    code {{ white-space: pre-wrap; overflow-wrap: anywhere; word-break: break-word; background: rgba(18,61,84,0.05); padding: 2px 4px; border-radius: 6px; }}
    .detail-stack {{ display: grid; gap: 8px; }}
    .detail-line {{ display: grid; gap: 4px; padding: 8px; background: rgba(18,61,84,0.04); border-radius: 12px; }}
    .detail-label {{ font-weight: 700; }}
    .detail-key {{ color: var(--muted); font-size: 8pt; text-transform: uppercase; letter-spacing: 0.04em; }}
    @media (max-width: 900px) {{
      form {{ grid-template-columns: 1fr; }}
    }}
  </style>
</head>
<body>
  <main>
    <section class="toolbar">
      <div class="panel">
        <h2>Search Events</h2>
        <form method="get" action="/">
          <input type="text" name="q" value="{search_value}" placeholder="attack, ip, matched, detail, raw log">
          <select name="event">
            <option value="">all events</option>
            {''.join(f"<option value='{html.escape(name or 'unknown')}' {'selected' if selected_event == name else ''}>{html.escape(name or 'unknown')}</option>" for name in summary.keys())}
          </select>
          <input type="number" name="limit" min="1" max="500" value="{limit}">
          <button type="submit">Apply</button>
        </form>
      </div>
    </section>

    <section class="panel">
      <h2>Recent Events</h2>
      <div class="table-wrap">
        <table>
          <thead>
            <tr>
              <th>ID</th>
              <th>Timestamp</th>
              <th>Level</th>
              <th>Event</th>
              <th>Attack</th>
              <th>Source</th>
              <th>Dest</th>
              <th>Detect ms</th>
              <th>Detail</th>
            </tr>
          </thead>
          <tbody>
            {''.join(table_rows) or "<tr><td colspan='9'>no rows</td></tr>"}
          </tbody>
        </table>
      </div>
    </section>
  </main>
</body>
</html>"""
    return body.encode("utf-8")


def make_handler(db_file: pathlib.Path):
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            parsed = urlparse(self.path)
            params = parse_qs(parsed.query)
            if parsed.path == "/api/events":
                self.serve_api(params)
                return
            selected_event = params.get("event", [None])[0]
            query = params.get("q", [None])[0]
            limit = min(max(int(params.get("limit", ["100"])[0]), 1), 500)
            conn = db_connect(db_file)
            try:
                overview = fetch_overview(conn)
                summary = fetch_summary(conn)
                rows = fetch_events(conn, selected_event, query, limit)
            finally:
                conn.close()

            body = render_page(overview, summary, rows, selected_event, query, limit)
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def serve_api(self, params) -> None:
            selected_event = params.get("event", [None])[0]
            query = params.get("q", [None])[0]
            limit = min(max(int(params.get("limit", ["100"])[0]), 1), 500)
            conn = db_connect(db_file)
            try:
                rows = fetch_events(conn, selected_event, query, limit)
                payload = [dict(row) for row in rows]
            finally:
                conn.close()

            body = json.dumps(payload, ensure_ascii=False, indent=2).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, fmt: str, *args) -> None:
            return

    return Handler


def main() -> int:
    parser = argparse.ArgumentParser(description="Serve IPS event DB as a tiny web UI")
    parser.add_argument(
        "--db-file",
        default=str(pathlib.Path(__file__).resolve().with_name("ips_events.db")),
        help="SQLite database path",
    )
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8090)
    args = parser.parse_args()

    db_file = pathlib.Path(args.db_file)
    if not db_file.exists():
        raise SystemExit(f"db file not found: {db_file}")

    server = ThreadingHTTPServer((args.host, args.port), make_handler(db_file))
    print(f"serving IPS viewer on http://{args.host}:{args.port}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
