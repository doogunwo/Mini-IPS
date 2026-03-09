#!/usr/bin/env python3
"""
OWASP CRS .conf 파일에서 @rx 정규식만 추출해 JSONL 룰 파일로 변환한다.
"""

from __future__ import annotations

import argparse
import json
import pathlib
import re
import sys
from typing import Iterable


FILE_POLICY_MAP = (
    (re.compile(r"REQUEST-913-.*SCANNER", re.I), ("POLICY_SCANNER", "SCANNER")),
    (re.compile(r"REQUEST-920-.*PROTOCOL", re.I), ("POLICY_PROTOCOL_VIOLATION", "PROTOCOL_VIOLATION")),
    (re.compile(r"REQUEST-921-.*PROTOCOL", re.I), ("POLICY_PROTOCOL_VIOLATION", "PROTOCOL_VIOLATION")),
    (re.compile(r"REQUEST-922-.*MULTIPART", re.I), ("POLICY_PROTOCOL_VIOLATION", "PROTOCOL_VIOLATION")),
    (re.compile(r"REQUEST-930-.*LFI|REQUEST-930-.*TRAVERSAL", re.I), ("POLICY_DIRECTORY_TRAVERS", "DIRECTORY_TRAVERSAL")),
    (re.compile(r"REQUEST-931-.*RFI|REQUEST-932-.*RCE", re.I), ("POLICY_COMMAND_INJECTION", "COMMAND_INJECTION")),
    (re.compile(r"REQUEST-933-.*PHP|REQUEST-934-.*GENERIC|REQUEST-944-.*JAVA", re.I), ("POLICY_COMMAND_INJECTION", "COMMAND_INJECTION")),
    (re.compile(r"REQUEST-941-.*XSS", re.I), ("POLICY_XSS", "XSS")),
    (re.compile(r"REQUEST-942-.*SQLI", re.I), ("POLICY_SQL_INJECTION", "SQL_INJECTION")),
    (re.compile(r"REQUEST-943-.*SESSION", re.I), ("POLICY_APP_WEAK", "APP_WEAK")),
    (re.compile(r"RESPONSE-950-.*DATA-LEAKAGES", re.I), ("POLICY_INFO_LEAK", "INFO_LEAK")),
    (re.compile(r"RESPONSE-951-.*DATA-LEAKAGES", re.I), ("POLICY_INFO_LEAK", "INFO_LEAK")),
    (re.compile(r"RESPONSE-952-.*DATA-LEAKAGES", re.I), ("POLICY_INFO_LEAK", "INFO_LEAK")),
    (re.compile(r"RESPONSE-953-.*DATA-LEAKAGES", re.I), ("POLICY_INFO_LEAK", "INFO_LEAK")),
)

CTX_PATTERNS = (
    (re.compile(r"\bRESPONSE_(?:BODY|CONTENT)\b", re.I), "RESPONSE_BODY"),
    (re.compile(r"\bREQUEST_(?:BODY|XML|BASENAME|FILENAME)\b", re.I), "BODY"),
    (re.compile(r"\bREQUEST_(?:HEADERS|COOKIES)\b", re.I), "HEADERS"),
    (re.compile(r"\b(?:ARGS|ARGS_NAMES)\b", re.I), "ARGS"),
    (re.compile(r"\b(?:REQUEST_URI|REQUEST_FILENAME|REQUEST_LINE|QUERY_STRING)\b", re.I), "URI"),
)

SEVERITY_TO_PRIO = {
    "CRITICAL": 5,
    "ERROR": 4,
    "WARNING": 3,
    "NOTICE": 2,
}

RULE_START_RE = re.compile(r"^\s*SecRule\s+", re.M)
RX_RE = re.compile(r"@rx\s+(.+?)(?=\s*(?:\"?,\s*|t:|tag:|msg:|id:|phase:|severity:|ver:|rev:|setvar:|ctl:|chain\b|$))", re.I | re.S)
ID_RE = re.compile(r"\bid\s*:\s*['\"]?(\d+)", re.I)
SEVERITY_RE = re.compile(r"\bseverity\s*:\s*['\"]?([A-Z]+)", re.I)
MSG_RE = re.compile(r"\bmsg\s*:\s*(['\"])(.*?)\1", re.I | re.S)
TAG_RE = re.compile(r"\btag\s*:\s*(['\"])(.*?)\1", re.I | re.S)


def split_rules(text: str) -> list[str]:
    starts = [m.start() for m in RULE_START_RE.finditer(text)]
    if not starts:
        return []
    starts.append(len(text))
    return [text[starts[i]:starts[i + 1]].strip() for i in range(len(starts) - 1)]


def normalize_ws(value: str) -> str:
    return re.sub(r"\s+", " ", value).strip()


def unquote_modsec(value: str) -> str:
    value = value.strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in ("'", '"'):
        value = value[1:-1]
    return value.replace("\\\n", "").replace("\\\r\n", "").strip()


def infer_policy(conf_name: str) -> tuple[str, str]:
    for pattern, mapped in FILE_POLICY_MAP:
        if pattern.search(conf_name):
            return mapped
    return ("POLICY_COMMAND_INJECTION", "COMMAND_INJECTION")


def infer_ctx(variables: str, conf_name: str, pid: str) -> str:
    for pattern, ctx in CTX_PATTERNS:
        if pattern.search(variables):
            return ctx

    if conf_name.upper().startswith("RESPONSE-"):
        return "RESPONSE_BODY"
    if pid == "POLICY_PROTOCOL_VIOLATION":
        return "HEADERS"
    if pid == "POLICY_DIRECTORY_TRAVERS":
        return "URI"
    if pid in ("POLICY_INFO_LEAK", "POLICY_WEBSHELL", "POLICY_XSS"):
        return "BODY"
    return "ARGS"


def extract_rule(rule_text: str, source_file: pathlib.Path) -> dict | None:
    first_line = rule_text.splitlines()[0] if rule_text else ""
    rx_match = RX_RE.search(rule_text)
    if not rx_match:
        return None

    pattern = normalize_ws(unquote_modsec(rx_match.group(1)))
    if not pattern:
        return None

    fields_text = normalize_ws(rule_text)
    id_match = ID_RE.search(fields_text)
    severity_match = SEVERITY_RE.search(fields_text)
    msg_match = MSG_RE.search(rule_text)
    tags = [normalize_ws(m.group(2)) for m in TAG_RE.finditer(rule_text)]

    variables = ""
    if len(first_line.split()) >= 2:
        variables = first_line.split(None, 2)[1]

    pid, pname = infer_policy(source_file.name)
    ctx = infer_ctx(variables, source_file.name, pid)
    severity = severity_match.group(1).upper() if severity_match else "NOTICE"
    prio = SEVERITY_TO_PRIO.get(severity, 2)

    return {
        "rid": int(id_match.group(1)) if id_match else None,
        "pid": pid,
        "pname": pname,
        "pat": pattern,
        "prio": prio,
        "ctx": ctx,
        "msg": normalize_ws(msg_match.group(2)) if msg_match else "",
        "tags": tags,
        "source": source_file.name,
        "variables": variables,
    }


def iter_conf_files(root: pathlib.Path) -> Iterable[pathlib.Path]:
    return sorted(path for path in root.rglob("*.conf") if path.is_file())


def main() -> int:
    parser = argparse.ArgumentParser(description="CRS .conf 파일에서 @rx 규칙을 JSONL로 추출한다.")
    parser.add_argument(
        "--input-dir",
        default=str(pathlib.Path(__file__).resolve().parents[1] / "crs_conf"),
        help="CRS .conf 루트 디렉터리",
    )
    parser.add_argument(
        "--output",
        default=str(pathlib.Path(__file__).resolve().parents[1] / "generated" / "rules.jsonl"),
        help="생성할 JSONL 파일 경로",
    )
    args = parser.parse_args()

    input_dir = pathlib.Path(args.input_dir).resolve()
    output = pathlib.Path(args.output).resolve()

    if not input_dir.is_dir():
        print(f"input dir not found: {input_dir}", file=sys.stderr)
        return 1

    conf_files = list(iter_conf_files(input_dir))
    if not conf_files:
        print(f"no .conf files found under: {input_dir}", file=sys.stderr)
        return 1

    output.parent.mkdir(parents=True, exist_ok=True)

    count = 0
    with output.open("w", encoding="utf-8") as fp:
        for conf_file in conf_files:
            text = conf_file.read_text(encoding="utf-8", errors="ignore")
            for rule_text in split_rules(text):
                record = extract_rule(rule_text, conf_file)
                if not record:
                    continue
                fp.write(json.dumps(record, ensure_ascii=False) + "\n")
                count += 1

    print(f"wrote {count} rules to {output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
