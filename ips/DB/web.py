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
            "COALESCE(event_id, '') LIKE ? OR "
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
        params.extend([like, like, like, like, like, like, like, like])

    where_sql = ""
    if clauses:
        where_sql = "WHERE " + " AND ".join(clauses)

    params.append(limit)
    return conn.execute(
        f"""
        SELECT id, event_id, ts, level, event, action_name, attack, where_name, src_ip, src_port,
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
    if event == "rst_request" or event == "block_inject":
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


def parse_rule_entry(entry: str) -> tuple[str, str, str]:
    parts = entry.split("|", 2)
    if len(parts) == 3:
        return parts[0], parts[1], parts[2]
    if len(parts) == 2:
        return parts[0], "-", parts[1]
    return "-", "-", entry


def parse_text_entry(entry: str) -> tuple[str, str]:
    parts = entry.split("|", 1)
    if len(parts) == 2:
        return parts[0], parts[1]
    return "-", entry


def render_raw_line_toggle(row: sqlite3.Row) -> str:
    raw_line = row["raw_line"] or ""
    if not raw_line:
        return ""
    event_id = html.escape(str(row["event_id"] or row["id"] or "-"))
    return (
        "<details class='raw-toggle'>"
        f"<summary>Raw Line ({event_id})</summary>"
        f"<pre class='raw-log'>{html.escape(raw_line)}</pre>"
        "</details>"
    )


def render_detail_html(row: sqlite3.Row) -> str:
    event = row["event"] or ""
    if event == "rst_request":
        return "<span class='muted-cell'>-</span>"

    if event == "detect":
        rules = split_serialized(row["matched"])
        texts = split_serialized(row["matched_texts"])
        lines = []
        pair_len = min(len(rules), len(texts))

        if pair_len == 0 and rules:
            pair_len = len(rules)

        for idx in range(pair_len):
            rule_ctx, policy, regex = (
                parse_rule_entry(rules[idx]) if idx < len(rules) else ("-", "-", "-")
            )
            text_ctx, matched_text = (
                parse_text_entry(texts[idx])
                if idx < len(texts)
                else (rule_ctx, "[matched text unavailable]")
            )
            context = text_ctx if text_ctx != "-" else rule_ctx
            lines.append(
                "<div class='detail-line'>"
                f"<div><span class='detail-label'>{html.escape(context)}</span></div>"
                f"<div><span class='detail-key'>attack</span>=<code>{html.escape(policy)}</code></div>"
                f"<div><span class='detail-key'>regex</span>=<code>{html.escape(regex)}</code></div>"
                f"<div><span class='detail-key'>match</span>=<code>{html.escape(matched_text)}</code></div>"
                "</div>"
            )

        omitted = max(len(rules), len(texts)) - pair_len
        if omitted > 0:
            lines.append(
                "<div class='detail-line'>"
                "<div><span class='detail-label'>DETAIL</span></div>"
                f"<div><span class='detail-key'>note</span>=<code>{omitted} additional entries omitted or truncated</code></div>"
                "</div>"
            )
        if lines:
            return (
                f"<div class='detail-stack'>{''.join(lines)}</div>"
                f"{render_raw_line_toggle(row)}"
            )

    detail = row["detail"] or row["raw_line"] or row["matched_texts"] or row["matched"] or ""
    if not detail:
        return "<span class='muted-cell'>-</span>"
    return (
        f"<code>{html.escape(detail)}</code>"
        f"{render_raw_line_toggle(row)}"
    )


def render_page(overview, summary, rows, selected_event: Optional[str], query: Optional[str], limit: int) -> bytes:
    table_rows = []
    for row in rows:
        tone = event_tone(row["event"] or "", row["level"] or "")
        date_part, time_part = format_timestamp_parts(row["ts"])
        where_name = row["where_name"] or "-"
        source = f"{row['src_ip'] or '-'}:{row['src_port'] or '-'}"
        dest = f"{row['dst_ip'] or '-'}:{row['dst_port'] or '-'}"
        score_line = f"score={row['score'] or '-'} threshold={row['threshold'] or '-'} matches={row['match_count'] or '-'}"
        display_id = row["event_id"] or str(row["id"])
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
            f"<td class='mono'>{html.escape(str(display_id))}</td>"
            f"<td><div class='ts-date'>{html.escape(date_part)}</div><div class='ts-time mono'>{html.escape(time_part)}</div><div class='sub'>{html.escape(where_name)}</div></td>"
            f"<td><span class='pill level-{html.escape((row['level'] or 'INFO').lower())}'>{html.escape(row['level'] or '')}</span></td>"
            f"<td><span class='pill event-{html.escape(tone)}'>{html.escape(row['event'] or '')}</span><div class='sub'>{html.escape(score_line)}</div></td>"
            f"<td class='mono'>{html.escape(source)}</td>"
            f"<td class='mono'>{html.escape(dest)}</td>"
            f"<td class='mono'>{html.escape(detect_display)}</td>"
            f"<td>{detail_html}</td>"
            "</tr>"
        )

    search_value = html.escape(query or "")
    event_options = "".join(
        f"<option value='{html.escape(name or 'unknown')}' "
        f"{'selected' if selected_event == name else ''}>"
        f"{html.escape(name or 'unknown')}</option>"
        for name in summary.keys()
    )
    summary_rows = "".join(
        "<div class='event-row'>"
        f"<span class='event-name'>{html.escape(name or 'unknown')}</span>"
        f"<span class='event-count mono'>{count}</span>"
        "</div>"
        for name, count in list(summary.items())[:10]
    )
    latest_ts = html.escape(str(overview.get("latest") or "-"))
    body = f"""<!doctype html>
<html lang="ko">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta http-equiv="refresh" content="15">
  <title>Mini-IPS DB Console</title>
  <style>
    :root {{
      --shell: #171c24;
      --shell-line: #313a4a;
      --shell-ink: #eef3ff;
      --bg: #eef3f9;
      --bg-2: #dde8f5;
      --panel: rgba(255, 255, 255, 0.88);
      --line: #d8e2ef;
      --ink: #101828;
      --muted: #667085;
      --accent: #2f6fed;
      --good: #0f9d76;
      --warn: #c08b24;
      --danger: #d04f37;
      --info: #2c7fb8;
      --shadow: 0 26px 60px rgba(15, 23, 42, 0.10);
      --radius: 24px;
    }}
    * {{ box-sizing: border-box; }}
    body {{
      margin: 0;
      font-family: "Pretendard", "Noto Sans KR", "Segoe UI", sans-serif;
      color: var(--ink);
      background:
        radial-gradient(circle at top left, rgba(47,111,237,0.14), transparent 24%),
        radial-gradient(circle at bottom right, rgba(15,157,118,0.12), transparent 20%),
        linear-gradient(180deg, var(--bg-2), var(--bg));
    }}
    .app-shell {{ min-height: 100vh; }}
    .sidebar {{
      position: fixed;
      inset: 0 auto 0 0;
      width: 252px;
      background: linear-gradient(180deg, var(--shell), #121720 76%);
      color: var(--shell-ink);
      border-right: 1px solid var(--shell-line);
      padding: 22px 18px;
      display: flex;
      flex-direction: column;
      gap: 18px;
    }}
    .brand {{
      padding-bottom: 16px;
      border-bottom: 1px solid rgba(255,255,255,0.10);
    }}
    .brand-mark {{
      display: inline-flex;
      align-items: center;
      gap: 10px;
      font-size: 24px;
      font-weight: 800;
      letter-spacing: -0.04em;
    }}
    .brand-dot {{
      width: 12px;
      height: 12px;
      border-radius: 999px;
      background: linear-gradient(135deg, #63c96b, #2f6fed);
      box-shadow: 0 0 0 6px rgba(99,201,107,0.12);
    }}
    .brand-copy {{
      margin-top: 8px;
      color: rgba(238,243,255,0.68);
      font-size: 13px;
      line-height: 1.5;
    }}
    .nav-group {{ display: grid; gap: 8px; }}
    .nav-label {{
      color: rgba(238,243,255,0.55);
      font-size: 11px;
      letter-spacing: 0.14em;
      text-transform: uppercase;
      padding: 0 10px;
    }}
    .nav-link {{
      display: block;
      padding: 13px 14px;
      border-radius: 16px;
      text-decoration: none;
      background: rgba(255,255,255,0.03);
      border: 1px solid transparent;
      transition: 0.18s ease;
      color: inherit;
    }}
    .nav-link:hover {{
      background: rgba(255,255,255,0.08);
      border-color: rgba(255,255,255,0.08);
    }}
    .nav-link.active {{
      background: linear-gradient(180deg, rgba(47,111,237,0.22), rgba(47,111,237,0.12));
      border-color: rgba(84,148,255,0.35);
      box-shadow: inset 0 1px 0 rgba(255,255,255,0.08);
    }}
    .nav-title {{ font-weight: 700; font-size: 14px; }}
    .nav-sub {{
      margin-top: 4px;
      color: rgba(238,243,255,0.65);
      font-size: 12px;
      line-height: 1.4;
    }}
    .content {{
      margin-left: 252px;
      padding: 24px;
    }}
    .topbar {{
      display: flex;
      justify-content: space-between;
      align-items: flex-start;
      gap: 16px;
      margin-bottom: 18px;
    }}
    .title h1 {{
      margin: 0;
      font-size: 34px;
      line-height: 1.05;
      letter-spacing: -0.05em;
    }}
    .title p {{
      margin: 8px 0 0;
      color: var(--muted);
      font-size: 14px;
    }}
    .header-chips {{
      display: flex;
      gap: 10px;
      flex-wrap: wrap;
      justify-content: flex-end;
    }}
    .chip {{
      display: inline-flex;
      align-items: center;
      gap: 8px;
      padding: 10px 12px;
      border-radius: 999px;
      background: rgba(255,255,255,0.72);
      border: 1px solid rgba(216,226,239,0.95);
      color: var(--muted);
      font-size: 12px;
      font-weight: 700;
      box-shadow: 0 10px 24px rgba(15, 23, 42, 0.04);
    }}
    .chip strong {{ color: var(--ink); }}
    .stats-grid {{
      display: grid;
      grid-template-columns: repeat(4, minmax(0, 1fr));
      gap: 14px;
      margin-bottom: 18px;
    }}
    .card, .panel {{
      background: var(--panel);
      backdrop-filter: blur(10px);
      border: 1px solid rgba(255,255,255,0.65);
      border-radius: var(--radius);
      box-shadow: var(--shadow);
    }}
    .card {{
      padding: 18px;
      min-height: 126px;
      display: grid;
      align-content: space-between;
      gap: 10px;
    }}
    .card-label {{
      color: var(--muted);
      font-size: 12px;
      text-transform: uppercase;
      letter-spacing: 0.12em;
      font-weight: 800;
    }}
    .card-value {{
      font-size: 34px;
      font-weight: 800;
      letter-spacing: -0.05em;
    }}
    .card-sub {{
      color: var(--muted);
      font-size: 13px;
      line-height: 1.5;
    }}
    .layout {{
      display: grid;
      grid-template-columns: minmax(0, 1.55fr) 320px;
      gap: 18px;
    }}
    .panel {{ padding: 18px; }}
    .panel-head {{
      display: flex;
      justify-content: space-between;
      align-items: flex-start;
      gap: 12px;
      margin-bottom: 14px;
    }}
    .panel-title {{
      margin: 0;
      font-size: 22px;
      letter-spacing: -0.04em;
    }}
    .panel-copy {{
      margin: 6px 0 0;
      color: var(--muted);
      font-size: 13px;
    }}
    form {{
      display: grid;
      grid-template-columns: 1fr 190px 110px 100px;
      gap: 10px;
      margin-bottom: 16px;
    }}
    input, select, button {{
      width: 100%;
      padding: 13px 14px;
      border-radius: 16px;
      border: 1px solid var(--line);
      background: rgba(255,255,255,0.94);
      color: var(--ink);
      font: inherit;
    }}
    input:focus, select:focus {{
      outline: none;
      border-color: rgba(47,111,237,0.45);
      box-shadow: 0 0 0 4px rgba(47,111,237,0.10);
    }}
    button {{
      border-color: var(--accent);
      background: linear-gradient(180deg, #4d83f3, var(--accent));
      color: #fff;
      font-weight: 800;
      cursor: pointer;
    }}
    .table-wrap {{
      overflow: auto;
      border-radius: 18px;
      border: 1px solid var(--line);
      background: rgba(255,255,255,0.72);
    }}
    table {{
      width: 100%;
      border-collapse: collapse;
      min-width: 980px;
      font-size: 13px;
    }}
    th, td {{
      padding: 14px 12px;
      border-bottom: 1px solid rgba(216,226,239,0.92);
      text-align: left;
      vertical-align: top;
    }}
    th {{
      position: sticky;
      top: 0;
      background: rgba(239,245,253,0.96);
      z-index: 1;
      color: var(--muted);
      font-size: 11px;
      text-transform: uppercase;
      letter-spacing: 0.12em;
    }}
    .mono {{ font-family: "SFMono-Regular", Menlo, Consolas, monospace; }}
    .ts-date {{ font-weight: 700; }}
    .ts-time {{ margin-top: 4px; color: var(--muted); }}
    .sub {{ margin-top: 6px; color: var(--muted); font-size: 12px; }}
    .muted-cell {{ color: var(--muted); }}
    .pill {{
      display: inline-flex;
      align-items: center;
      padding: 7px 10px;
      border-radius: 999px;
      font-size: 11px;
      font-weight: 800;
      letter-spacing: 0.06em;
      text-transform: uppercase;
    }}
    .level-warn {{ background: rgba(192,139,36,0.12); color: var(--warn); }}
    .level-error {{ background: rgba(208,79,55,0.12); color: var(--danger); }}
    .level-info {{ background: rgba(44,127,184,0.12); color: var(--info); }}
    .event-threat {{ background: rgba(208,79,55,0.12); color: var(--danger); }}
    .event-block {{ background: rgba(192,139,36,0.14); color: var(--warn); }}
    .event-error {{ background: rgba(208,79,55,0.12); color: var(--danger); }}
    .event-info {{ background: rgba(44,127,184,0.12); color: var(--info); }}
    .tone-threat td:first-child,
    .tone-block td:first-child,
    .tone-error td:first-child {{ box-shadow: inset 4px 0 0 transparent; }}
    .tone-threat td:first-child {{ box-shadow: inset 4px 0 0 var(--danger); }}
    .tone-block td:first-child {{ box-shadow: inset 4px 0 0 var(--warn); }}
    .tone-error td:first-child {{ box-shadow: inset 4px 0 0 #8d1f1f; }}
    code {{
      white-space: pre-wrap;
      overflow-wrap: anywhere;
      word-break: break-word;
      background: rgba(47,111,237,0.08);
      color: #1e3a5f;
      padding: 3px 6px;
      border-radius: 8px;
    }}
    .detail-stack {{ display: grid; gap: 8px; }}
    .detail-line {{
      display: grid;
      gap: 5px;
      padding: 10px;
      background: rgba(47,111,237,0.05);
      border: 1px solid rgba(47,111,237,0.08);
      border-radius: 14px;
    }}
    .detail-label {{ font-weight: 700; }}
    .detail-key {{
      color: var(--muted);
      font-size: 10px;
      text-transform: uppercase;
      letter-spacing: 0.08em;
    }}
    .raw-toggle {{
      margin-top: 8px;
      padding: 10px 12px;
      border-radius: 12px;
      border: 1px solid rgba(47,111,237,0.12);
      background: rgba(47,111,237,0.04);
    }}
    .raw-toggle summary {{
      cursor: pointer;
      font-size: 12px;
      font-weight: 700;
      color: #24456e;
      list-style: none;
    }}
    .raw-toggle summary::-webkit-details-marker {{
      display: none;
    }}
    .raw-log {{
      margin: 10px 0 0;
      padding: 12px;
      max-height: 320px;
      overflow: auto;
      white-space: pre-wrap;
      overflow-wrap: anywhere;
      word-break: break-word;
      border-radius: 10px;
      background: rgba(15, 23, 42, 0.06);
      color: #17263b;
      font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
      font-size: 11px;
      line-height: 1.5;
    }}
    .event-list {{ display: grid; gap: 10px; }}
    .event-row {{
      display: flex;
      justify-content: space-between;
      align-items: center;
      gap: 12px;
      padding: 12px 14px;
      border-radius: 16px;
      background: rgba(248,250,252,0.88);
      border: 1px solid var(--line);
    }}
    .event-name {{
      font-weight: 700;
      text-transform: capitalize;
    }}
    .event-count {{ color: var(--muted); }}
    .side-note {{
      margin-top: 14px;
      padding: 14px;
      border-radius: 18px;
      background: linear-gradient(180deg, rgba(47,111,237,0.10), rgba(47,111,237,0.04));
      border: 1px solid rgba(47,111,237,0.12);
      color: #21426b;
      font-size: 13px;
      line-height: 1.6;
    }}
    .side-note strong {{
      display: block;
      margin-bottom: 6px;
      color: var(--ink);
    }}
    @media (max-width: 1260px) {{
      .stats-grid {{ grid-template-columns: repeat(3, minmax(0, 1fr)); }}
      .layout {{ grid-template-columns: 1fr; }}
    }}
    @media (max-width: 900px) {{
      .sidebar {{
        position: static;
        width: auto;
        border-right: 0;
        border-bottom: 1px solid var(--shell-line);
      }}
      .content {{ margin-left: 0; padding: 18px 14px 28px; }}
      .topbar {{ flex-direction: column; }}
      .header-chips {{ justify-content: flex-start; }}
      .stats-grid {{ grid-template-columns: repeat(2, minmax(0, 1fr)); }}
      form {{ grid-template-columns: 1fr; }}
    }}
    @media (max-width: 640px) {{
      .stats-grid {{ grid-template-columns: 1fr; }}
      .title h1 {{ font-size: 28px; }}
      .card-value {{ font-size: 28px; }}
    }}
  </style>
</head>
<body>
  <div class="app-shell">
    <aside class="sidebar">
      <section class="brand">
        <div class="brand-mark"><span class="brand-dot"></span><span>Mini-IPS</span></div>
      </section>
      <section class="nav-group">
        <div class="nav-label">Sections</div>
        <a class="nav-link active" href="/" data-target-port="8090">
          <div class="nav-title">DB</div>
          <div class="nav-sub">SQLite 적재 이벤트 조회와 필터링</div>
        </a>
        <a class="nav-link" href="/" data-target-port="8091">
          <div class="nav-title">Monitor</div>
          <div class="nav-sub">실시간 PPS · 재조립 · 처리량 모니터</div>
        </a>
      </section>
    </aside>

    <main class="content">
      <section class="topbar">
        <div class="title">
          <h1>이벤트 대시보드</h1>
        </div>
        <div class="header-chips">
          <span class="chip"><strong>Latest</strong> {latest_ts}</span>
          <span class="chip"><strong>Filter</strong> {html.escape(selected_event or 'all')}</span>
          <span class="chip"><strong>Refresh</strong> 15s</span>
        </div>
      </section>

      <section class="stats-grid">
        <article class="card">
          <div class="card-label">Total Events</div>
          <div class="card-value">{overview["total"]}</div>
          <div class="card-sub">적재된 전체 보안 이벤트</div>
        </article>
        <article class="card">
          <div class="card-label">Detect</div>
          <div class="card-value">{overview["detect"]}</div>
          <div class="card-sub">탐지 이벤트 누적</div>
        </article>
        <article class="card">
          <div class="card-label">RST Requests</div>
          <div class="card-value">{overview["rst"]}</div>
          <div class="card-sub">능동 차단 요청 누적</div>
        </article>
        <article class="card">
          <div class="card-label">Errors</div>
          <div class="card-value">{overview["errors"]}</div>
          <div class="card-sub">레벨 ERROR 기록</div>
        </article>
      </section>

      <section class="layout">
        <section class="panel">
          <div class="panel-head">
            <div>
              <h2 class="panel-title">Recent Events</h2>
              <p class="panel-copy">이벤트 ID, 방향, 탐지 시간과 상세 매칭 내용을 한 화면에서 본다.</p>
            </div>
          </div>
          <form method="get" action="/">
            <input type="text" name="q" value="{search_value}" placeholder="attack, ip, matched, detail, raw log">
            <select name="event">
              <option value="">all events</option>
              {event_options}
            </select>
            <input type="number" name="limit" min="1" max="500" value="{limit}">
            <button type="submit">Apply</button>
          </form>
          <div class="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>Event ID</th>
                  <th>Timestamp</th>
                  <th>Level</th>
                  <th>Event</th>
                  <th>Source</th>
                  <th>Dest</th>
                  <th>Detect ms</th>
                  <th>Detail</th>
                </tr>
              </thead>
              <tbody>
                {''.join(table_rows) or "<tr><td colspan='8'>no rows</td></tr>"}
              </tbody>
            </table>
          </div>
        </section>

        <aside class="panel">
          <div class="panel-head">
            <div>
              <h2 class="panel-title">Event Mix</h2>
              <p class="panel-copy">최근 적재된 카테고리 분포와 현재 조회 상태</p>
            </div>
          </div>
          <div class="event-list">
            {summary_rows or "<div class='muted-cell'>no event summary</div>"}
          </div>
        </aside>
      </section>
    </main>
  </div>

  <script>
    (() => {{
      const proto = window.location.protocol;
      const host = window.location.hostname || "127.0.0.1";
      document.querySelectorAll("[data-target-port]").forEach((link) => {{
        const port = link.getAttribute("data-target-port");
        link.setAttribute("href", `${{proto}}//${{host}}:${{port}}/`);
      }});
    }})();
  </script>
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
