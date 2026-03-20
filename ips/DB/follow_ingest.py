#!/usr/bin/env python3
import argparse
import pathlib
import sqlite3
import time

from ingest_logs import compact_raw_line, init_db, parse_kv_line, should_store, to_int


def format_ingest_message(fields: dict[str, str]) -> str | None:
    event = fields.get("event")
    if event != "rst_request":
        return None
    return (
        f"ingested: ts={fields.get('ts', '-')} "
        f"level={fields.get('level', '-')} "
        f"event=rst_request "
        f"src_ip={fields.get('src_ip', '-')} src_port={fields.get('src_port', '-')} "
        f"dst_ip={fields.get('dst_ip', '-')} dst_port={fields.get('dst_port', '-')} "
        f"rc_ab={fields.get('rc_ab', '-')} rc_ba={fields.get('rc_ba', '-')}"
    )


def insert_line(conn: sqlite3.Connection, line: str) -> int:
    fields = parse_kv_line(line)
    if not fields or not should_store(fields):
        return 0

    before = conn.total_changes
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
    conn.commit()
    return conn.total_changes - before


def follow_file(log_file: pathlib.Path, db_file: pathlib.Path, poll_interval: float, start_at_end: bool) -> int:
    db_file.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(db_file)
    try:
        init_db(conn)
        with log_file.open("r", encoding="utf-8", errors="replace") as handle:
            if start_at_end:
                handle.seek(0, 2)

            while True:
                line = handle.readline()
                if not line:
                    time.sleep(poll_interval)
                    continue

                line = line.strip()
                if not line:
                    continue

                inserted = insert_line(conn, line)
                if inserted:
                    fields = parse_kv_line(line)
                    msg = format_ingest_message(fields)
                    if msg is not None:
                        print(msg, flush=True)
    except KeyboardInterrupt:
        return 0
    finally:
        conn.close()


def main() -> int:
    parser = argparse.ArgumentParser(description="Continuously ingest IPS logs into SQLite")
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
    parser.add_argument(
        "--poll-interval",
        type=float,
        default=0.5,
        help="seconds between file polls",
    )
    parser.add_argument(
        "--start-at-end",
        action="store_true",
        help="ignore existing file contents and only ingest new lines",
    )
    args = parser.parse_args()

    log_file = pathlib.Path(args.log_file)
    db_file = pathlib.Path(args.db_file)

    if not log_file.exists():
        raise SystemExit(f"log file not found: {log_file}")

    return follow_file(log_file, db_file, args.poll_interval, args.start_at_end)


if __name__ == "__main__":
    raise SystemExit(main())
