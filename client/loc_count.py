#!/usr/bin/env python3
import argparse
import os
import sys

DEFAULT_EXTS = {
    ".c", ".h", ".cpp", ".hpp", ".cc",
    ".py", ".js", ".ts", ".java", ".go", ".rs",
    ".sh", ".bash", ".zsh", ".ps1",
    ".html", ".css", ".scss", ".json", ".yaml", ".yml",
    ".md",
}

SKIP_DIRS = {
    ".git", ".hg", ".svn",
    "__pycache__", "node_modules", "venv", ".venv",
    "build", "dist", "out", "target", "bin", "obj",
}


def parse_args():
    p = argparse.ArgumentParser(description="Count lines of code in a folder.")
    p.add_argument("path", nargs="?", default=".", help="root folder (default: .)")
    p.add_argument("--ext", default="", help="comma-separated extensions (e.g. .c,.h,.py)")
    p.add_argument("--all", action="store_true", help="count all files regardless of extension")
    p.add_argument("--include-hidden", action="store_true", help="include hidden files/dirs")
    p.add_argument("--by-ext", action="store_true", help="print counts per extension")
    return p.parse_args()


def should_skip_dir(dirname, include_hidden):
    if not include_hidden and dirname.startswith('.'):
        return True
    return dirname in SKIP_DIRS


def count_lines_in_file(path):
    try:
        with open(path, "r", errors="ignore") as f:
            return sum(1 for _ in f)
    except (OSError, UnicodeError):
        return 0


def main():
    args = parse_args()
    root = os.path.abspath(args.path)
    if not os.path.isdir(root):
        print(f"not a directory: {root}")
        return 1

    exts = None
    if not args.all:
        if args.ext.strip():
            exts = {e if e.startswith('.') else f".{e}" for e in args.ext.split(',') if e.strip()}
        else:
            exts = DEFAULT_EXTS

    total_files = 0
    total_lines = 0
    per_ext = {}

    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if not should_skip_dir(d, args.include_hidden)]
        for name in filenames:
            if not args.include_hidden and name.startswith('.'):
                continue
            path = os.path.join(dirpath, name)
            _, ext = os.path.splitext(name)
            if exts is not None and ext not in exts:
                continue
            lines = count_lines_in_file(path)
            total_files += 1
            total_lines += lines
            per_ext[ext] = per_ext.get(ext, 0) + lines

    print(f"root: {root}")
    print(f"files: {total_files}")
    print(f"lines: {total_lines}")

    if args.by_ext:
        for ext, lines in sorted(per_ext.items(), key=lambda x: (-x[1], x[0])):
            label = ext if ext else "(no_ext)"
            print(f"{label}: {lines}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
