#!/usr/bin/env python3
"""Read-only, zero-dependency Python AST indexer for legacy automation suites.

Never imports or executes target Python code. Extracts class inheritance chains,
methods, call targets, command/endpoint string templates, module constants, and
topology-parser indicators so agents can distill clean atomic CapabilityCards.
"""

import argparse
import ast
import json
import os
import re
import sys

SKIP_DIRS = {
    ".git",
    ".hg",
    ".svn",
    "__pycache__",
    ".venv",
    "venv",
    "env",
    "node_modules",
    ".tox",
    ".mypy_cache",
    ".pytest_cache",
    "dist",
    "build",
}

PARSER_IMPORTS = {
    "xml",
    "xml.etree",
    "xml.etree.ElementTree",
    "xml.dom",
    "lxml",
    "json",
    "yaml",
    "configparser",
    "ConfigParser",
    "toml",
    "tomllib",
    "csv",
    "openpyxl",
}

CMD_HINT_RE = re.compile(
    r"(?:^|\s)(?:ip\s+|ifconfig|ethtool|iscsiadm|nvme\s+|multipath|fio\s+|dd\s+|"
    r"sg_|lsblk|lsscsi|dmesg|grep\s+|awk\s+|sed\s+|systemctl|service\s+|"
    r"pidof|pgrep|pkill|kill\s+|mount\s+|umount\s+|mkfs|curl\s+|python3?\s+|"
    r"sh\s+|bash\s+|/api/v\d+|/redfish/|/dev/shm/|/proc/)",
    re.IGNORECASE,
)


def _node_to_name(node):
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        parent = _node_to_name(node.value)
        return "{}.{}".format(parent, node.attr) if parent else node.attr
    if isinstance(node, ast.Subscript):
        return _node_to_name(node.value)
    return ""


def _extract_string_value(node):
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if hasattr(ast, "Str") and isinstance(node, ast.Str):
        return node.s
    if isinstance(node, ast.JoinedStr):
        parts = []
        for item in node.values:
            if isinstance(item, ast.Constant) and isinstance(item.value, str):
                parts.append(item.value)
            elif hasattr(ast, "Str") and isinstance(item, ast.Str):
                parts.append(item.s)
            elif isinstance(item, ast.FormattedValue):
                expr_name = _node_to_name(item.value) or "expr"
                parts.append("{" + expr_name + "}")
        return "".join(parts)
    if isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Add, ast.Mod)):
        left = _extract_string_value(node.left)
        right = _extract_string_value(node.right)
        if left and right:
            return left + (" % " if isinstance(node.op, ast.Mod) else "") + right
        return left or right
    return ""


def _looks_like_command_or_endpoint(text):
    clean = text.strip()
    if len(clean) < 4 or len(clean) > 400:
        return False
    if CMD_HINT_RE.search(clean):
        return True
    if clean.startswith("/") and "/" in clean[1:] and " " not in clean:
        return True
    if ("{" in clean and "}" in clean) and (" " in clean or "/" in clean):
        return True
    return False


def _collect_func_details(fn_node):
    calls = []
    seen_calls = set()
    literals = []
    seen_literals = set()

    for sub in ast.walk(fn_node):
        if isinstance(sub, ast.Call):
            name = _node_to_name(sub.func)
            if name and name not in seen_calls and len(calls) < 25:
                seen_calls.add(name)
                calls.append(name)
        elif isinstance(sub, (ast.Constant, ast.JoinedStr)) or (hasattr(ast, "Str") and isinstance(sub, ast.Str)):
            text = _extract_string_value(sub)
            if text and _looks_like_command_or_endpoint(text):
                compact = " ".join(text.split())
                if compact not in seen_literals and len(literals) < 12:
                    seen_literals.add(compact)
                    literals.append(compact)

    args = [arg.arg for arg in fn_node.args.args if arg.arg != "self"]
    doc = ast.get_docstring(fn_node) or ""
    first_doc = doc.strip().splitlines()[0][:120] if doc.strip() else ""
    return {
        "name": fn_node.name,
        "line": fn_node.lineno,
        "args": args,
        "doc": first_doc,
        "calls": calls,
        "command_hints": literals,
    }


def index_file(file_path, rel_path):
    try:
        with open(file_path, "r", encoding="utf-8", errors="replace") as fh:
            source = fh.read()
        tree = ast.parse(source, filename=rel_path)
    except Exception as exc:
        return {"file": rel_path, "parse_error": str(exc)}

    imports = []
    parser_signals = []
    constants = {}
    classes = []
    functions = []

    for node in tree.body:
        if isinstance(node, ast.Import):
            for alias in node.names:
                imports.append(alias.name)
                if alias.name in PARSER_IMPORTS or alias.name.split(".")[0] in PARSER_IMPORTS:
                    parser_signals.append(alias.name)
        elif isinstance(node, ast.ImportFrom):
            mod = node.module or ""
            if mod:
                imports.append(mod)
                if mod in PARSER_IMPORTS or mod.split(".")[0] in PARSER_IMPORTS:
                    parser_signals.append(mod)
        elif isinstance(node, ast.Assign):
            val = _extract_string_value(node.value)
            if val and len(val) <= 240:
                for target in node.targets:
                    if isinstance(target, ast.Name) and len(constants) < 30:
                        constants[target.id] = " ".join(val.split())
        elif isinstance(node, ast.ClassDef):
            bases = [_node_to_name(b) for b in node.bases]
            bases = [b for b in bases if b]
            methods = []
            class_consts = {}
            for item in node.body:
                if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    methods.append(_collect_func_details(item))
                elif isinstance(item, ast.Assign):
                    val = _extract_string_value(item.value)
                    if val and len(val) <= 240:
                        for target in item.targets:
                            if isinstance(target, ast.Name) and len(class_consts) < 20:
                                class_consts[target.id] = " ".join(val.split())
            classes.append({
                "name": node.name,
                "line": node.lineno,
                "bases": bases,
                "constants": class_consts,
                "methods": methods,
            })
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            functions.append(_collect_func_details(node))

    return {
        "file": rel_path,
        "parser_signals": sorted(set(parser_signals)),
        "constants": constants,
        "classes": classes,
        "functions": functions,
    }


def _matches_query(file_entry, query):
    if not query:
        return True
    q = query.lower()
    if q in file_entry.get("file", "").lower():
        return True
    for key, val in file_entry.get("constants", {}).items():
        if q in key.lower() or q in str(val).lower():
            return True
    for cls in file_entry.get("classes", []):
        if q in cls["name"].lower() or any(q in b.lower() for b in cls["bases"]):
            return True
        for m in cls["methods"]:
            if q in m["name"].lower() or any(q in h.lower() for h in m["command_hints"]):
                return True
    for fn in file_entry.get("functions", []):
        if q in fn["name"].lower() or any(q in h.lower() for h in fn["command_hints"]):
            return True
    return False


def main():
    parser = argparse.ArgumentParser(description="Read-only Python AST indexer for pangea-verify")
    parser.add_argument("root", help="Root directory of legacy Python automation codebase")
    parser.add_argument("--query", default="", help="Optional case-insensitive filter on file/class/method/command")
    parser.add_argument("--max-files", type=int, default=200, help="Maximum number of Python files to scan")
    parser.add_argument("--topo-only", action="store_true", help="Only return files with topology/config parser signals")
    args = parser.parse_args()

    root = os.path.abspath(args.root)
    if not os.path.isdir(root):
        sys.stderr.write("root directory not found: {}\n".format(root))
        sys.exit(1)

    scanned = 0
    truncated = False
    files = []
    class_hierarchy = {}

    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(d for d in dirnames if d not in SKIP_DIRS and not d.startswith("."))
        for fname in sorted(filenames):
            if not fname.endswith(".py"):
                continue
            if scanned >= args.max_files:
                truncated = True
                break
            full = os.path.join(dirpath, fname)
            rel = os.path.relpath(full, root).replace("\\", "/")
            scanned += 1
            entry = index_file(full, rel)
            for cls in entry.get("classes", []):
                class_hierarchy[cls["name"]] = {
                    "file": rel,
                    "line": cls["line"],
                    "bases": cls["bases"],
                }
            if args.topo_only and not entry.get("parser_signals"):
                continue
            if _matches_query(entry, args.query):
                files.append(entry)
        if truncated:
            break

    result = {
        "schema_version": 1,
        "root": root,
        "scanned_files": scanned,
        "matched_files": len(files),
        "truncated": truncated,
        "class_hierarchy": class_hierarchy,
        "files": files,
    }
    sys.stdout.write(json.dumps(result, ensure_ascii=False, indent=2) + "\n")


if __name__ == "__main__":
    main()
