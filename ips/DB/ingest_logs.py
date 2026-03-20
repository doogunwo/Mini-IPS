#!/usr/bin/env python3
import argparse
import pathlib
import sqlite3
from typing import Dict, Optional


INTERESTING_EVENTS = {
    "detect",
    "rst_request",
    "block_inject",
    "block_page_send",
    "stream_error",
    "detect_error",
}

PARSE_KEYS = {
    "event_id",
    "ts",
    "level",
    "event",
    "action",
    "attack",
    "where",
    "src_ip",
    "src_port",
    "dst_ip",
    "dst_port",
    "score",
    "threshold",
    "match_count",
    "matched",
    "matched_rules",
    "matched_texts",
    "detect_us",
    "detect_ms",
    "detail",
}

VALUE_LIMITS = {
    "matched": 4096,
    "matched_rules": 4096,
    "matched_texts": 4096,
    "detail": 4096,
}

DEFAULT_VALUE_LIMIT = 512
RAW_LINE_LIMIT = 4096


def parse_kv_line(line: str) -> Dict[str, str]:
    parsed: Dict[str, str] = {}
    n = len(line)
    i = 0

    while i < n:
        while i < n and line[i].isspace():
            i += 1
        if i >= n:
            break

        key_start = i
        while i < n and not line[i].isspace() and line[i] != "=":
            i += 1
        if i >= n or line[i] != "=":
            while i < n and not line[i].isspace():
                i += 1
            continue

        key = line[key_start:i]
        i += 1

        want_key = key in PARSE_KEYS
        limit = VALUE_LIMITS.get(key, DEFAULT_VALUE_LIMIT)
        truncated = False

        if i < n and line[i] == "\"":
            i += 1
            if want_key:
                chars = []
            while i < n:
                ch = line[i]
                if ch == "\\" and i + 1 < n:
                    next_ch = line[i + 1]
                    if want_key:
                        if len(chars) < limit:
                            chars.append(next_ch)
                        else:
                            truncated = True
                    i += 2
                    continue
                if ch == "\"":
                    i += 1
                    break
                if want_key:
                    if len(chars) < limit:
                        chars.append(ch)
                    else:
                        truncated = True
                i += 1

            if want_key:
                value = "".join(chars)
                if truncated:
                    value += " ... [truncated]"
                parsed[key] = value
            continue

        value_start = i
        while i < n and not line[i].isspace():
            i += 1
        if want_key:
            value = line[value_start:i]
            if len(value) > limit:
                value = value[:limit] + " ... [truncated]"
            parsed[key] = value

    return parsed


def compact_raw_line(line: str, fields: Dict[str, str]) -> str:
    event_id = fields.get("event_id")
    prefix = f"event_id={event_id} " if event_id else ""
    available = RAW_LINE_LIMIT - len(prefix)
    if available < 0:
        available = 0
    if len(line) <= available:
        return prefix + line
    return (
        prefix
        + line[:available]
        + f" ... [truncated len={len(line)}]"
    )


def init_db(conn: sqlite3.Connection) -> None:
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS ips_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            event_id TEXT,
            ts TEXT,
            level TEXT,
            event TEXT,
            action_name TEXT,
            attack TEXT,
            where_name TEXT,
            src_ip TEXT,
            src_port INTEGER,
            dst_ip TEXT,
            dst_port INTEGER,
            score INTEGER,
            threshold INTEGER,
            match_count INTEGER,
            matched TEXT,
            matched_texts TEXT,
            detect_us INTEGER,
            detect_ms INTEGER,
            detail TEXT,
            raw_line TEXT NOT NULL UNIQUE,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
        """
    )
    existing = {row[1] for row in conn.execute("PRAGMA table_info(ips_events)").fetchall()}
    if "event_id" not in existing:
        conn.execute("ALTER TABLE ips_events ADD COLUMN event_id TEXT")
    if "score" not in existing:
        conn.execute("ALTER TABLE ips_events ADD COLUMN score INTEGER")
    if "threshold" not in existing:
        conn.execute("ALTER TABLE ips_events ADD COLUMN threshold INTEGER")
    if "match_count" not in existing:
        conn.execute("ALTER TABLE ips_events ADD COLUMN match_count INTEGER")
    if "matched_texts" not in existing:
        conn.execute("ALTER TABLE ips_events ADD COLUMN matched_texts TEXT")
    if "detect_us" not in existing:
        conn.execute("ALTER TABLE ips_events ADD COLUMN detect_us INTEGER")
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_ips_events_ts ON ips_events(ts DESC)"
    )
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_ips_events_event ON ips_events(event)"
    )
    conn.commit()


def to_int(value: Optional[str]) -> Optional[int]:
    if value is None or value == "":
        return None
    try:
        return int(value)
    except ValueError:
        return None


def should_store(fields: Dict[str, str]) -> bool:
    event = fields.get("event")
    if event in INTERESTING_EVENTS:
        return True
    return fields.get("level") == "ERROR"


def ingest_file(log_file: pathlib.Path, db_file: pathlib.Path) -> int:
    db_file.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(db_file)
    try:
        init_db(conn)
        inserted = 0
        with log_file.open("r", encoding="utf-8", errors="replace") as handle:
            for raw_line in handle:
                line = raw_line.strip()
                if not line:
                    continue
                fields = parse_kv_line(line)
                if not fields or not should_store(fields):
                    continue
                conn.execute(
                    """
                    INSERT OR IGNORE INTO ips_events (
                        event_id, ts, level, event, action_name, attack, where_name,
                        src_ip, src_port, dst_ip, dst_port, score, threshold,
                        match_count, matched, matched_texts, detect_us, detect_ms,
                        detail, raw_line
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        fields.get("event_id"),
                        fields.get("ts"),
                        fields.get("level"),
                        fields.get("event"),
                        fields.get("action"),
                        fields.get("attack"),
                        fields.get("where"),
                        fields.get("src_ip"),
                        to_int(fields.get("src_port")),
                        fields.get("dst_ip"),
                        to_int(fields.get("dst_port")),
                        to_int(fields.get("score")),
                        to_int(fields.get("threshold")),
                        to_int(fields.get("match_count")),
                        fields.get("matched_rules") or fields.get("matched"),
                        fields.get("matched_texts"),
                        to_int(fields.get("detect_us")),
                        to_int(fields.get("detect_ms")),
                        fields.get("detail"),
                        compact_raw_line(line, fields),
                    ),
                )
                inserted += conn.total_changes - inserted
        conn.commit()
        return inserted
    finally:
        conn.close()


def main() -> int:
    parser = argparse.ArgumentParser(description="Ingest IPS structured logs into SQLite")
    default_root = pathlib.Path(__file__).resolve().parents[2]
    parser.add_argument(
        "--log-file",
        default=str(default_root / "runtime-logs" / "ips" / "ips.log"),
        help="structured IPS log file path",
    )
    parser.add_argument(
        "--db-file",
        default=str(pathlib.Path(__file__).resolve().with_name("ips_events.db")),
        help="SQLite database path",
    )
    args = parser.parse_args()

    log_file = pathlib.Path(args.log_file)
    db_file = pathlib.Path(args.db_file)

    if not log_file.exists():
        raise SystemExit(f"log file not found: {log_file}")

    inserted = ingest_file(log_file, db_file)
    print(f"ingested {inserted} events into {db_file}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
