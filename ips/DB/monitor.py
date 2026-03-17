#!/usr/bin/env python3
"""
실시간 IPS 성능 모니터 웹 UI.

SQLite나 이벤트 로그를 보지 않고 monitor.log의 주기적 stats 라인만 follow 한다.
"""

import argparse
import json
import os
import pathlib
import threading
import time
from collections import deque
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Deque
from urllib.parse import urlparse

from ingest_logs import parse_kv_line


DEFAULT_POLL_INTERVAL = 0.5
DEFAULT_PORT = 8091
DEFAULT_HISTORY_LINES = 120
DEFAULT_RECENT_SAMPLES = 60


def resolve_default_log_file() -> pathlib.Path:
    env_path = os.getenv("MONITOR_LOG_FILE")
    if env_path:
        return pathlib.Path(env_path)

    repo_root = pathlib.Path(__file__).resolve().parents[1]
    local_path = repo_root / "logs" / "monitor.log"
    if local_path.exists():
        return local_path

    return pathlib.Path("/logs/monitor.log")


def safe_int(text: str | None) -> int:
    if text is None or text == "":
        return 0
    try:
        return int(text)
    except ValueError:
        return 0


@dataclass
class MonitorSample:
    ts: str
    interval_ms: int
    worker_count: int
    pps: int
    req_ps: int
    detect_ps: int
    queue_depth: int
    reasm_in_order_ps: int
    reasm_out_of_order_ps: int
    reasm_trimmed_ps: int
    total_packets: int
    total_reqs: int
    total_detect: int
    total_reasm_in_order: int
    total_reasm_out_of_order: int
    total_reasm_trimmed: int

    def to_dict(self) -> dict[str, object]:
        return {
            "ts": self.ts,
            "interval_ms": self.interval_ms,
            "worker_count": self.worker_count,
            "pps": self.pps,
            "req_ps": self.req_ps,
            "detect_ps": self.detect_ps,
            "queue_depth": self.queue_depth,
            "reasm_in_order_ps": self.reasm_in_order_ps,
            "reasm_out_of_order_ps": self.reasm_out_of_order_ps,
            "reasm_trimmed_ps": self.reasm_trimmed_ps,
            "total_packets": self.total_packets,
            "total_reqs": self.total_reqs,
            "total_detect": self.total_detect,
            "total_reasm_in_order": self.total_reasm_in_order,
            "total_reasm_out_of_order": self.total_reasm_out_of_order,
            "total_reasm_trimmed": self.total_reasm_trimmed,
        }


class MonitorState:
    def __init__(self, sample_limit: int) -> None:
        self.lock = threading.Lock()
        self.total_lines = 0
        self.stats_lines = 0
        self.latest: MonitorSample | None = None
        self.samples: Deque[MonitorSample] = deque(maxlen=sample_limit)

    def ingest_line(self, line: str) -> None:
        fields = parse_kv_line(line)
        if not fields:
            return

        with self.lock:
            self.total_lines += 1

            if fields.get("event") != "stats":
                return

            sample = MonitorSample(
                ts=fields.get("ts", "-"),
                interval_ms=safe_int(fields.get("interval_ms")),
                worker_count=safe_int(fields.get("worker_count")),
                pps=safe_int(fields.get("pps")),
                req_ps=safe_int(fields.get("req_ps")),
                detect_ps=safe_int(fields.get("detect_ps")),
                queue_depth=safe_int(fields.get("queue_depth")),
                reasm_in_order_ps=safe_int(fields.get("reasm_in_order_ps")),
                reasm_out_of_order_ps=safe_int(fields.get("reasm_out_of_order_ps")),
                reasm_trimmed_ps=safe_int(fields.get("reasm_trimmed_ps")),
                total_packets=safe_int(fields.get("total_packets")),
                total_reqs=safe_int(fields.get("total_reqs")),
                total_detect=safe_int(fields.get("total_detect")),
                total_reasm_in_order=safe_int(fields.get("total_reasm_in_order")),
                total_reasm_out_of_order=safe_int(
                    fields.get("total_reasm_out_of_order")
                ),
                total_reasm_trimmed=safe_int(fields.get("total_reasm_trimmed")),
            )
            self.stats_lines += 1
            self.latest = sample
            self.samples.appendleft(sample)

    def snapshot(self) -> dict[str, object]:
        with self.lock:
            latest = self.latest.to_dict() if self.latest is not None else None
            return {
                "total_lines": self.total_lines,
                "stats_lines": self.stats_lines,
                "latest": latest,
                "samples": [sample.to_dict() for sample in self.samples],
            }


class LogFollower(threading.Thread):
    def __init__(
        self,
        log_file: pathlib.Path,
        state: MonitorState,
        poll_interval: float,
        history_lines: int,
    ) -> None:
        super().__init__(daemon=True)
        self.log_file = log_file
        self.state = state
        self.poll_interval = poll_interval
        self.history_lines = history_lines
        self.stop_event = threading.Event()

    def _load_recent_history(self) -> None:
        if self.history_lines <= 0 or not self.log_file.exists():
            return

        try:
            with self.log_file.open("r", encoding="utf-8", errors="replace") as handle:
                lines = deque(handle, maxlen=self.history_lines)
        except OSError:
            return

        for line in lines:
            line = line.strip()
            if line:
                self.state.ingest_line(line)

    def _open_tail(self):
        handle = self.log_file.open("r", encoding="utf-8", errors="replace")
        handle.seek(0, os.SEEK_END)
        stat = self.log_file.stat()
        return handle, stat.st_ino

    def run(self) -> None:
        self._load_recent_history()

        while not self.stop_event.is_set():
            if not self.log_file.exists():
                time.sleep(self.poll_interval)
                continue

            try:
                handle, inode = self._open_tail()
            except OSError:
                time.sleep(self.poll_interval)
                continue

            try:
                while not self.stop_event.is_set():
                    line = handle.readline()
                    if line:
                        line = line.strip()
                        if line:
                            self.state.ingest_line(line)
                        continue

                    try:
                        stat = self.log_file.stat()
                    except OSError:
                        break

                    if stat.st_ino != inode or stat.st_size < handle.tell():
                        break

                    time.sleep(self.poll_interval)
            finally:
                handle.close()

    def stop(self) -> None:
        self.stop_event.set()


def render_index() -> bytes:
    body = """<!doctype html>
<html lang="ko">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Mini-IPS Runtime Monitor</title>
  <style>
    :root {
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
      --hot: #d04f37;
      --good: #0f9d76;
      --warn: #c08b24;
      --shadow: 0 26px 60px rgba(15, 23, 42, 0.10);
      --radius: 24px;
    }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      color: var(--ink);
      font-family: "Pretendard", "Noto Sans KR", "Segoe UI", sans-serif;
      background:
        radial-gradient(circle at top left, rgba(47,111,237,0.14), transparent 24%),
        radial-gradient(circle at bottom right, rgba(15,157,118,0.12), transparent 20%),
        linear-gradient(180deg, var(--bg-2), var(--bg));
    }
    .app-shell { min-height: 100vh; }
    .sidebar {
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
    }
    .brand {
      padding-bottom: 16px;
      border-bottom: 1px solid rgba(255,255,255,0.10);
    }
    .brand-mark {
      display: inline-flex;
      align-items: center;
      gap: 10px;
      font-size: 24px;
      font-weight: 800;
      letter-spacing: -0.04em;
    }
    .brand-dot {
      width: 12px;
      height: 12px;
      border-radius: 999px;
      background: linear-gradient(135deg, #63c96b, #2f6fed);
      box-shadow: 0 0 0 6px rgba(99,201,107,0.12);
    }
    .brand-copy {
      margin-top: 8px;
      color: rgba(238,243,255,0.68);
      font-size: 13px;
      line-height: 1.5;
    }
    .nav-group { display: grid; gap: 8px; }
    .nav-label {
      color: rgba(238,243,255,0.55);
      font-size: 11px;
      letter-spacing: 0.14em;
      text-transform: uppercase;
      padding: 0 10px;
    }
    .nav-link {
      display: block;
      padding: 13px 14px;
      border-radius: 16px;
      text-decoration: none;
      background: rgba(255,255,255,0.03);
      border: 1px solid transparent;
      transition: 0.18s ease;
      color: inherit;
    }
    .nav-link:hover {
      background: rgba(255,255,255,0.08);
      border-color: rgba(255,255,255,0.08);
    }
    .nav-link.active {
      background: linear-gradient(180deg, rgba(47,111,237,0.22), rgba(47,111,237,0.12));
      border-color: rgba(84,148,255,0.35);
      box-shadow: inset 0 1px 0 rgba(255,255,255,0.08);
    }
    .nav-title { font-weight: 700; font-size: 14px; }
    .nav-sub {
      margin-top: 4px;
      color: rgba(238,243,255,0.65);
      font-size: 12px;
      line-height: 1.4;
    }
    .content {
      margin-left: 252px;
      padding: 24px;
    }
    .hero, .panel {
      background: var(--panel);
      border: 1px solid rgba(255,255,255,0.65);
      border-radius: var(--radius);
      box-shadow: var(--shadow);
    }
    .topbar {
      display: flex;
      justify-content: space-between;
      align-items: flex-start;
      gap: 16px;
      margin-bottom: 18px;
    }
    .hero { padding: 22px 24px; flex: 1; }
    .hero h1 { margin: 0; font-size: 34px; line-height: 1.05; letter-spacing: -0.05em; }
    .hero p { margin: 8px 0 0; color: var(--muted); font-size: 14px; }
    .overview {
      display: grid;
      grid-template-columns: repeat(4, minmax(0, 1fr));
      gap: 14px;
      margin-bottom: 18px;
    }
    .card {
      background: var(--panel);
      border: 1px solid rgba(255,255,255,0.65);
      border-radius: var(--radius);
      padding: 16px 18px;
      box-shadow: var(--shadow);
    }
    .label {
      color: var(--muted);
      font-size: 12px;
      text-transform: uppercase;
      letter-spacing: 0.08em;
    }
    .value {
      margin-top: 8px;
      font-size: 30px;
      font-weight: 700;
    }
    .sub {
      margin-top: 6px;
      color: var(--muted);
      font-size: 13px;
    }
    .grid {
      display: grid;
      grid-template-columns: 1.1fr 0.9fr;
      gap: 18px;
    }
    .panel { padding: 18px; }
    .panel h2 { margin: 0 0 14px; font-size: 22px; letter-spacing: -0.04em; }
    .bars { display: grid; gap: 12px; }
    .bar-row { display: grid; gap: 6px; }
    .bar-head {
      display: flex;
      justify-content: space-between;
      align-items: baseline;
      gap: 10px;
    }
    .bar-label { font-weight: 700; }
    .bar-count { color: var(--muted); font-family: "SFMono-Regular", Menlo, monospace; }
    .bar-track {
      height: 14px;
      background: rgba(47,111,237,0.08);
      border-radius: 999px;
      overflow: hidden;
      border: 1px solid rgba(47,111,237,0.06);
    }
    .bar-fill {
      height: 100%;
      border-radius: 999px;
      width: 0%;
      transition: width 0.3s ease;
    }
    .fill-main { background: linear-gradient(90deg, #2f6fed, #0f9d76); }
    .fill-hot { background: linear-gradient(90deg, #d04f37, #eb7c61); }
    .fill-warn { background: linear-gradient(90deg, #c08b24, #dcb24f); }
    .stat-list { display: grid; gap: 10px; }
    .stat-item {
      display: flex;
      justify-content: space-between;
      gap: 12px;
      padding-bottom: 8px;
      border-bottom: 1px dashed var(--line);
      font-size: 14px;
    }
    .stat-name { font-weight: 700; }
    .stat-value { color: var(--muted); font-family: "SFMono-Regular", Menlo, monospace; }
    .timeline-head {
      display: flex;
      justify-content: space-between;
      align-items: center;
      gap: 16px;
      margin-bottom: 12px;
      flex-wrap: wrap;
    }
    .timeline-copy {
      color: var(--muted);
      font-size: 13px;
    }
    .legend {
      display: flex;
      gap: 14px;
      flex-wrap: wrap;
    }
    .legend-item {
      display: inline-flex;
      align-items: center;
      gap: 8px;
      color: var(--muted);
      font-size: 12px;
      font-weight: 700;
    }
    .legend-swatch {
      width: 12px;
      height: 12px;
      border-radius: 999px;
    }
    .swatch-pps { background: #2f6fed; }
    .swatch-req { background: #0f9d76; }
    .swatch-detect { background: #d04f37; }
    .chart-frame {
      border-radius: 20px;
      border: 1px solid var(--line);
      background:
        linear-gradient(180deg, rgba(255,255,255,0.82), rgba(245,249,255,0.92));
      padding: 12px;
    }
    .chart-svg {
      width: 100%;
      height: 320px;
      display: block;
    }
    .chart-grid {
      stroke: rgba(103, 119, 147, 0.18);
      stroke-width: 1;
    }
    .chart-axis {
      stroke: rgba(103, 119, 147, 0.32);
      stroke-width: 1.2;
    }
    .chart-label {
      fill: var(--muted);
      font-size: 11px;
      font-family: "Pretendard", "Noto Sans KR", "Segoe UI", sans-serif;
    }
    .chart-line {
      fill: none;
      stroke-width: 3;
      stroke-linecap: round;
      stroke-linejoin: round;
    }
    .line-pps { stroke: #2f6fed; }
    .line-req { stroke: #0f9d76; }
    .line-detect { stroke: #d04f37; }
    .chart-empty {
      display: grid;
      place-items: center;
      height: 320px;
      color: var(--muted);
      font-size: 14px;
    }
    .mono { font-family: "SFMono-Regular", Menlo, monospace; }
    .muted { color: var(--muted); }
    @media (max-width: 1100px) {
      .overview { grid-template-columns: repeat(2, minmax(0, 1fr)); }
      .grid { grid-template-columns: 1fr; }
    }
    @media (max-width: 900px) {
      .sidebar {
        position: static;
        width: auto;
        border-right: 0;
        border-bottom: 1px solid var(--shell-line);
      }
      .content { margin-left: 0; padding: 18px 14px 28px; }
      .topbar { flex-direction: column; }
    }
    @media (max-width: 700px) {
      .overview { grid-template-columns: 1fr; }
      .hero h1 { font-size: 28px; }
      .value { font-size: 24px; }
    }
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
        <a class="nav-link" href="/" data-target-port="8090">
          <div class="nav-title">DB</div>
          <div class="nav-sub">이벤트 검색, 탐지 상세, 적재 결과 조회</div>
        </a>
        <a class="nav-link active" href="/" data-target-port="8091">
          <div class="nav-title">Monitor</div>
          <div class="nav-sub">PPS, 재조립 상태, 탐지 처리량 실시간 모니터</div>
        </a>
      </section>
    </aside>

    <main class="content">
      <section class="topbar">
        <section class="hero">
          <h1>시스템 대시보드</h1>
        </section>
      </section>

      <section class="overview">
        <div class="card">
          <div class="label">Packets / Sec</div>
          <div class="value" id="pps">0</div>
          <div class="sub" id="total-packets">total packets: 0</div>
        </div>
        <div class="card">
          <div class="label">HTTP Req / Sec</div>
          <div class="value" id="req-ps">0</div>
          <div class="sub" id="total-reqs">total reqs: 0</div>
        </div>
        <div class="card">
          <div class="label">Detect / Sec</div>
          <div class="value" id="detect-ps">0</div>
          <div class="sub" id="total-detect">total detect: 0</div>
        </div>
        <div class="card">
          <div class="label">Queue Depth</div>
          <div class="value" id="queue-depth">0</div>
          <div class="sub" id="interval-ms">interval: 0 ms</div>
        </div>
      </section>

      <section class="grid">
        <section class="panel">
          <h2>Reassembly Mix</h2>
          <div class="bars" id="reasm-bars"></div>
        </section>

      <section class="panel">
        <h2>Totals</h2>
        <div class="stat-list" id="totals-list"></div>
      </section>
    </section>

      <section class="panel" style="margin-top: 18px;">
        <div class="timeline-head">
          <div>
            <h2>Traffic Timeline</h2>
          </div>
          <div class="legend">
            <span class="legend-item"><span class="legend-swatch swatch-pps"></span>PPS</span>
            <span class="legend-item"><span class="legend-swatch swatch-req"></span>Req/s</span>
            <span class="legend-item"><span class="legend-swatch swatch-detect"></span>Detect/s</span>
          </div>
        </div>
        <div class="chart-frame">
          <div id="timeline-chart" class="chart-empty">waiting for stats...</div>
        </div>
      </section>
    </main>
  </div>

  <script>
    (() => {
      const proto = window.location.protocol;
      const host = window.location.hostname || "127.0.0.1";
      document.querySelectorAll("[data-target-port]").forEach((link) => {
        const port = link.getAttribute("data-target-port");
        link.setAttribute("href", `${proto}//${host}:${port}/`);
      });
    })();

    function esc(text) {
      return String(text ?? "")
        .replaceAll("&", "&amp;")
        .replaceAll("<", "&lt;")
        .replaceAll(">", "&gt;");
    }

    function renderBars(container, latest) {
      if (!latest) {
        container.innerHTML = `<div class="muted">waiting for stats...</div>`;
        return;
      }

      const rows = [
        { label: "In-Order / sec", value: latest.reasm_in_order_ps, cls: "fill-main" },
        { label: "Out-of-Order / sec", value: latest.reasm_out_of_order_ps, cls: "fill-hot" },
        { label: "Trimmed / sec", value: latest.reasm_trimmed_ps, cls: "fill-warn" },
        { label: "Detect / sec", value: latest.detect_ps, cls: "fill-main" }
      ];
      const maxValue = Math.max(...rows.map((row) => row.value), 1);

      container.innerHTML = rows.map((row) => {
        const ratio = (row.value / maxValue) * 100.0;
        return (
          `<div class="bar-row">` +
          `<div class="bar-head"><span class="bar-label">${esc(row.label)}</span>` +
          `<span class="bar-count">${esc(row.value)}</span></div>` +
          `<div class="bar-track"><div class="bar-fill ${row.cls}" style="width:${ratio.toFixed(2)}%"></div></div>` +
          `</div>`
        );
      }).join("");
    }

    function renderTotals(container, latest, payload) {
      if (!latest) {
        container.innerHTML = `<div class="muted">waiting for stats...</div>`;
        return;
      }

      const rows = [
        { name: "Stats Lines", value: payload.stats_lines },
        { name: "Log Lines", value: payload.total_lines },
        { name: "Total Reasm In-Order", value: latest.total_reasm_in_order },
        { name: "Total Reasm Out-of-Order", value: latest.total_reasm_out_of_order },
        { name: "Total Reasm Trimmed", value: latest.total_reasm_trimmed }
      ];

      container.innerHTML = rows.map((row) => (
        `<div class="stat-item">` +
        `<span class="stat-name">${esc(row.name)}</span>` +
        `<span class="stat-value">${esc(row.value)}</span>` +
        `</div>`
      )).join("");
    }

    function renderTimeline(container, samples) {
      if (!samples.length) {
        container.innerHTML = `<div class="chart-empty">waiting for stats...</div>`;
        return;
      }

      const ordered = [...samples].reverse();
      const width = 1080;
      const height = 320;
      const padLeft = 56;
      const padRight = 20;
      const padTop = 18;
      const padBottom = 34;
      const innerWidth = width - padLeft - padRight;
      const innerHeight = height - padTop - padBottom;
      const maxValue = Math.max(
        ...ordered.flatMap((row) => [row.pps, row.req_ps, row.detect_ps]),
        1
      );

      function xAt(index) {
        if (ordered.length === 1) {
          return padLeft + innerWidth / 2;
        }
        return padLeft + (innerWidth * index) / (ordered.length - 1);
      }

      function yAt(value) {
        return padTop + innerHeight - (value / maxValue) * innerHeight;
      }

      function buildPath(key) {
        return ordered.map((row, index) => {
          const prefix = index === 0 ? "M" : "L";
          return `${prefix}${xAt(index).toFixed(2)} ${yAt(row[key]).toFixed(2)}`;
        }).join(" ");
      }

      const grid = [0, 0.25, 0.5, 0.75, 1].map((ratio) => {
        const y = padTop + innerHeight - innerHeight * ratio;
        const value = Math.round(maxValue * ratio);
        return (
          `<line class="chart-grid" x1="${padLeft}" y1="${y.toFixed(2)}" x2="${width - padRight}" y2="${y.toFixed(2)}"></line>` +
          `<text class="chart-label" x="${padLeft - 10}" y="${(y + 4).toFixed(2)}" text-anchor="end">${esc(value)}</text>`
        );
      }).join("");

      const xLabels = ordered.filter((_, index) => {
        if (ordered.length <= 6) {
          return true;
        }
        return index === 0 || index === ordered.length - 1 || index % Math.ceil(ordered.length / 5) === 0;
      }).map((row, index, arr) => {
        const originalIndex = ordered.indexOf(row);
        const x = xAt(originalIndex);
        const stamp = String(row.ts || "").split("T").pop() || row.ts || "-";
        return `<text class="chart-label" x="${x.toFixed(2)}" y="${height - 8}" text-anchor="middle">${esc(stamp.slice(0, 8))}</text>`;
      }).join("");

      container.innerHTML =
        `<svg class="chart-svg" viewBox="0 0 ${width} ${height}" preserveAspectRatio="none">` +
        `${grid}` +
        `<line class="chart-axis" x1="${padLeft}" y1="${padTop}" x2="${padLeft}" y2="${padTop + innerHeight}"></line>` +
        `<line class="chart-axis" x1="${padLeft}" y1="${padTop + innerHeight}" x2="${width - padRight}" y2="${padTop + innerHeight}"></line>` +
        `<path class="chart-line line-pps" d="${buildPath("pps")}"></path>` +
        `<path class="chart-line line-req" d="${buildPath("req_ps")}"></path>` +
        `<path class="chart-line line-detect" d="${buildPath("detect_ps")}"></path>` +
        `${xLabels}` +
        `</svg>`;
    }

    async function refreshState() {
      try {
        const response = await fetch("/api/state", { cache: "no-store" });
        const payload = await response.json();
        const latest = payload.latest;

        if (latest) {
          document.getElementById("pps").textContent = latest.pps;
          document.getElementById("req-ps").textContent = latest.req_ps;
          document.getElementById("detect-ps").textContent = latest.detect_ps;
          document.getElementById("queue-depth").textContent = latest.queue_depth;
          document.getElementById("interval-ms").textContent = `interval: ${latest.interval_ms} ms`;
          document.getElementById("total-packets").textContent = `total packets: ${latest.total_packets}`;
          document.getElementById("total-reqs").textContent = `total reqs: ${latest.total_reqs}`;
          document.getElementById("total-detect").textContent = `total detect: ${latest.total_detect}`;
        }

        renderBars(document.getElementById("reasm-bars"), latest);
        renderTotals(document.getElementById("totals-list"), latest, payload);
        renderTimeline(document.getElementById("timeline-chart"), payload.samples);
      } catch (err) {
        console.error(err);
      }
    }

    refreshState();
    setInterval(refreshState, 1000);
  </script>
</body>
</html>
"""
    return body.encode("utf-8")


def make_handler(state: MonitorState):
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            parsed = urlparse(self.path)
            if parsed.path == "/api/state":
                body = json.dumps(state.snapshot(), ensure_ascii=False).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/json; charset=utf-8")
                self.send_header("Cache-Control", "no-store")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
                return

            if parsed.path != "/":
                self.send_error(404)
                return

            body = render_index()
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Cache-Control", "no-store")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, fmt: str, *args) -> None:
            return

    return Handler


def main() -> int:
    parser = argparse.ArgumentParser(description="Serve live IPS runtime monitor")
    parser.add_argument(
        "--log-file",
        default=str(resolve_default_log_file()),
        help="monitor.log path",
    )
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT)
    parser.add_argument(
        "--poll-interval",
        type=float,
        default=DEFAULT_POLL_INTERVAL,
        help="seconds between file polls",
    )
    parser.add_argument(
        "--history-lines",
        type=int,
        default=DEFAULT_HISTORY_LINES,
        help="number of recent lines to pre-load before follow",
    )
    parser.add_argument(
        "--recent-samples",
        type=int,
        default=DEFAULT_RECENT_SAMPLES,
        help="recent stats rows to keep in memory",
    )
    args = parser.parse_args()

    log_file = pathlib.Path(args.log_file)
    state = MonitorState(sample_limit=max(args.recent_samples, 1))
    follower = LogFollower(
        log_file=log_file,
        state=state,
        poll_interval=max(args.poll_interval, 0.05),
        history_lines=max(args.history_lines, 0),
    )
    follower.start()

    server = ThreadingHTTPServer((args.host, args.port), make_handler(state))
    print(
        f"serving IPS runtime monitor on http://{args.host}:{args.port} "
        f"(log={log_file})"
    )
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        follower.stop()
        server.server_close()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
