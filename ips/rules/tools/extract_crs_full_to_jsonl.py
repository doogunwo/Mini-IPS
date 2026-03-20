#!/usr/bin/env python3
"""
OWASP CRS .conf 파일의 SecRule 전체를 JSONL로 변환한다.
"""

from __future__ import annotations

import argparse
import json
import pathlib
import re
import shlex
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
    (re.compile(r"RESPONSE-95\\d-.*DATA-LEAKAGES", re.I), ("POLICY_INFO_LEAK", "INFO_LEAK")),
    (re.compile(r"RESPONSE-955-.*WEB-SHELLS", re.I), ("POLICY_WEBSHELL", "WEBSHELL")),
)

SEVERITY_TO_PRIO = {
    "CRITICAL": 5,
    "ERROR": 4,
    "WARNING": 3,
    "NOTICE": 2,
}

RULE_START_RE = re.compile(r"^\s*SecRule\s+", re.M)
ID_RE = re.compile(r"\bid\s*:\s*['\"]?(\d+)", re.I)
SEVERITY_RE = re.compile(r"\bseverity\s*:\s*['\"]?([A-Z]+)", re.I)
MSG_RE = re.compile(r"\bmsg\s*:\s*(['\"])(.*?)\1", re.I | re.S)
TAG_RE = re.compile(r"\btag\s*:\s*(['\"])(.*?)\1", re.I | re.S)
PHASE_RE = re.compile(r"\bphase\s*:\s*(\d+)", re.I)
REV_RE = re.compile(r"\brev\s*:\s*['\"]?([^,'\"]+)", re.I)
VER_RE = re.compile(r"\bver\s*:\s*['\"]?([^,'\"]+)", re.I)
SETVAR_RE = re.compile(r"\bsetvar\s*:\s*['\"]?([^,'\"]+)", re.I)
CTL_RE = re.compile(r"\bctl\s*:\s*['\"]?([^,'\"]+)", re.I)
TRANSFORM_RE = re.compile(r"\bt\s*:\s*['\"]?([^,'\"]+)", re.I)


def normalize_ws(value: str) -> str:
    return re.sub(r"\s+", " ", value).strip()


def split_rules(text: str) -> list[str]:
    starts = [m.start() for m in RULE_START_RE.finditer(text)]
    if not starts:
        return []
    starts.append(len(text))
    return [text[starts[i]:starts[i + 1]].strip() for i in range(len(starts) - 1)]


def extract_rule_statement(rule_block: str) -> str:
    lines = rule_block.splitlines()
    if not lines:
        return ""

    collected: list[str] = []
    carry = False
    for idx, line in enumerate(lines):
        stripped = line.rstrip()
        if idx == 0 or carry:
            collected.append(stripped)
            carry = stripped.endswith("\\")
            continue
        break

    statement = "\n".join(collected).replace("\\\r\n", " ").replace("\\\n", " ")
    return normalize_ws(statement)


def infer_policy(conf_name: str) -> tuple[str, str]:
    for pattern, mapped in FILE_POLICY_MAP:
        if pattern.search(conf_name):
            return mapped
    return ("POLICY_COMMAND_INJECTION", "COMMAND_INJECTION")


def map_target_to_ctx(target: str, conf_name: str, pid: str) -> str | None:
    upper = target.upper()
    if "RESPONSE_BODY" in upper or "RESPONSE_CONTENT" in upper:
        return "RESPONSE_BODY"
    if any(tok in upper for tok in ("REQUEST_BODY", "XML", "FILES", "BASENAME", "FILENAME")):
        return "BODY"
    if any(tok in upper for tok in ("REQUEST_HEADERS", "REQUEST_COOKIES")):
        return "HEADERS"
    if "ARGS" in upper:
        return "ARGS"
    if any(tok in upper for tok in ("REQUEST_URI", "QUERY_STRING", "REQUEST_LINE")):
        return "URI"

    if conf_name.upper().startswith("RESPONSE-"):
        return "RESPONSE_BODY"
    if pid == "POLICY_PROTOCOL_VIOLATION":
        return "HEADERS"
    if pid == "POLICY_DIRECTORY_TRAVERS":
        return "URI"
    if pid in ("POLICY_INFO_LEAK", "POLICY_WEBSHELL", "POLICY_XSS"):
        return "BODY"
    return "ARGS"


def parse_targets(variables: str, conf_name: str, pid: str) -> list[str]:
    targets: list[str] = []
    for raw in re.split(r"[|,]", variables):
        raw = raw.strip()
        if not raw:
            continue
        mapped = map_target_to_ctx(raw, conf_name, pid)
        if mapped and mapped not in targets:
            targets.append(mapped)
    if not targets:
        targets.append(map_target_to_ctx("", conf_name, pid) or "ARGS")
    return targets


def parse_actions(raw_actions: str) -> dict:
    actions = {
        "transforms": [],
        "setvars": [],
        "ctls": [],
        "chain": False,
    }

    for match in TRANSFORM_RE.finditer(raw_actions):
        value = normalize_ws(match.group(1))
        if value and value not in actions["transforms"]:
            actions["transforms"].append(value)

    for match in SETVAR_RE.finditer(raw_actions):
        actions["setvars"].append(normalize_ws(match.group(1)))

    for match in CTL_RE.finditer(raw_actions):
        actions["ctls"].append(normalize_ws(match.group(1)))

    if re.search(r"(?:^|,)\s*chain(?:,|$)", raw_actions, re.I):
        actions["chain"] = True

    return actions


def load_data_file_values(base_dir: pathlib.Path, name: str) -> list[str]:
    data_path = base_dir / name
    if not data_path.is_file():
        return []

    values: list[str] = []
    for line in data_path.read_text(encoding="utf-8", errors="ignore").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        values.append(line)
    return values


def parse_operator(raw_operator: str, conf_dir: pathlib.Path) -> dict:
    negated = False
    value = raw_operator.strip()
    if value.startswith("!"):
        negated = True
        value = value[1:].strip()

    if value.startswith("@"):
        parts = value.split(None, 1)
        op = parts[0][1:]
        op_arg = parts[1].strip() if len(parts) > 1 else ""
    else:
        op = "streq"
        op_arg = value

    record = {
        "op": op,
        "op_negated": negated,
        "pat": op_arg,
    }

    if op == "pmFromFile" and op_arg:
        record["data_file"] = op_arg
        record["data_values"] = load_data_file_values(conf_dir, op_arg)

    return record


def extract_rule(rule_text: str, source_file: pathlib.Path) -> dict | None:
    statement = extract_rule_statement(rule_text)
    if not statement:
        return None

    try:
        tokens = shlex.split(statement, posix=True)
    except ValueError:
        return None

    if len(tokens) < 4 or tokens[0] != "SecRule":
        return None

    variables = tokens[1]
    raw_operator = tokens[2]
    raw_actions = tokens[3]

    pid, pname = infer_policy(source_file.name)
    targets = parse_targets(variables, source_file.name, pid)
    severity_match = SEVERITY_RE.search(raw_actions)
    severity = severity_match.group(1).upper() if severity_match else "NOTICE"
    prio = SEVERITY_TO_PRIO.get(severity, 2)
    actions = parse_actions(raw_actions)
    op_info = parse_operator(raw_operator, source_file.parent)
    msg_match = MSG_RE.search(raw_actions)

    record = {
        "rid": int(ID_RE.search(raw_actions).group(1)) if ID_RE.search(raw_actions) else None,
        "pid": pid,
        "pname": pname,
        "pat": op_info["pat"],
        "prio": prio,
        "ctx": targets[0],
        "targets": targets,
        "op": op_info["op"],
        "op_negated": op_info["op_negated"],
        "msg": normalize_ws(msg_match.group(2)) if msg_match else "",
        "tags": [normalize_ws(m.group(2)) for m in TAG_RE.finditer(raw_actions)],
        "phase": int(PHASE_RE.search(raw_actions).group(1)) if PHASE_RE.search(raw_actions) else None,
        "severity": severity,
        "transforms": actions["transforms"],
        "setvars": actions["setvars"],
        "ctls": actions["ctls"],
        "chain": actions["chain"],
        "variables": variables,
        "source": source_file.name,
        "ver": VER_RE.search(raw_actions).group(1) if VER_RE.search(raw_actions) else "",
        "rev": REV_RE.search(raw_actions).group(1) if REV_RE.search(raw_actions) else "",
    }

    if "data_file" in op_info:
        record["data_file"] = op_info["data_file"]
        record["data_values"] = op_info["data_values"]

    return record


def iter_conf_files(root: pathlib.Path) -> Iterable[pathlib.Path]:
    return sorted(
        path
        for path in root.rglob("*.conf")
        if path.is_file() and path.name.upper().startswith("REQUEST-")
    )


def main() -> int:
    parser = argparse.ArgumentParser(description="CRS .conf 파일의 SecRule 전체를 JSONL로 변환한다.")
    parser.add_argument(
        "--input-dir",
        default=str(pathlib.Path(__file__).resolve().parents[1] / "crs_conf"),
        help="CRS .conf 루트 디렉터리",
    )
    parser.add_argument(
        "--output",
        default=str(pathlib.Path(__file__).resolve().parents[1] / "generated" / "rules_full.jsonl"),
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
