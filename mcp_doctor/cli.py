"""mcp-doctor command-line interface.

Usage:
    mcp-doctor -- <command to launch your MCP server> [args...]
    mcp-doctor --json -- python -m my_server
    mcp-doctor --timeout 30 -- node build/index.js

Everything after ``--`` is the server launch command, passed as an explicit
argument list (no shell), so quoting/injection is a non-issue.
"""
from __future__ import annotations

import argparse
import json
import sys

from . import __version__
from .client import MCPStdioClient, MCPClientError
from .checks import run_all, ERROR, WARN, INFO

_COLOR = {ERROR: "\033[31m", WARN: "\033[33m", INFO: "\033[36m"}
_RESET = "\033[0m"
_LABEL = {ERROR: "ERROR", WARN: "WARN", INFO: "INFO"}


def _supports_color(stream) -> bool:
    return hasattr(stream, "isatty") and stream.isatty()


def _split_argv(argv: list):
    """Return (doctor_args, server_command) split on the first '--'."""
    if "--" in argv:
        i = argv.index("--")
        return argv[:i], argv[i + 1:]
    return argv, []


def main(argv=None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    doctor_args, server_cmd = _split_argv(argv)

    parser = argparse.ArgumentParser(
        prog="mcp-doctor",
        description="Health-check, lint, and security-audit an MCP server.",
        epilog="Put the server launch command after '--', e.g. "
               "mcp-doctor -- python -m my_server")
    parser.add_argument("--json", action="store_true",
                        help="emit findings as JSON (for CI or tooling)")
    parser.add_argument("--timeout", type=float, default=20.0,
                        help="seconds to wait for each server response (default 20)")
    parser.add_argument("--no-color", action="store_true", help="disable ANSI color")
    parser.add_argument("--version", action="version",
                        version=f"mcp-doctor {__version__}")
    args = parser.parse_args(doctor_args)

    if not server_cmd:
        parser.print_help(sys.stderr)
        print("\nerror: no server command given (put it after '--').",
              file=sys.stderr)
        return 2

    report = {"server": server_cmd, "ok": False, "server_info": {},
              "counts": {}, "findings": []}

    try:
        with MCPStdioClient(server_cmd, timeout=args.timeout) as client:
            info = client.initialize()
            tools = client.list_tools()
            resources = client.list_resources()
            prompts = client.list_prompts()
    except MCPClientError as exc:
        report["error"] = str(exc)
        if args.json:
            print(json.dumps(report, indent=2))
        else:
            _print_fatal(str(exc))
        return 1

    findings = run_all(info, tools, resources, prompts)
    report["server_info"] = {"name": info.name, "version": info.version,
                             "protocol_version": info.protocol_version}
    report["counts"] = {"tools": len(tools), "resources": len(resources),
                        "prompts": len(prompts),
                        "errors": sum(1 for f in findings if f.severity == ERROR),
                        "warnings": sum(1 for f in findings if f.severity == WARN)}
    report["findings"] = [f.as_dict() for f in findings]
    report["ok"] = report["counts"]["errors"] == 0

    if args.json:
        print(json.dumps(report, indent=2))
    else:
        _print_human(report, findings,
                     color=not args.no_color and _supports_color(sys.stdout))

    return 0 if report["ok"] else 1


def _print_fatal(msg: str) -> None:
    print(f"\n  mcp-doctor could not talk to the server.\n  {msg}\n", file=sys.stderr)


def _print_human(report, findings, color: bool) -> None:
    def c(sev, text):
        return f"{_COLOR[sev]}{text}{_RESET}" if color else text

    si = report["server_info"]
    counts = report["counts"]
    print()
    print(f"  mcp-doctor  ->  {si.get('name') or 'unknown server'} "
          f"{si.get('version') or ''}".rstrip())
    print(f"  protocol {si.get('protocol_version') or '?'}  |  "
          f"{counts['tools']} tools, {counts['resources']} resources, "
          f"{counts['prompts']} prompts")
    print()

    if not findings:
        print("  " + (c(INFO, "All checks passed. ") if color else "All checks passed. ")
              + "No issues found.")
        print()
        return

    order = {ERROR: 0, WARN: 1, INFO: 2}
    for f in sorted(findings, key=lambda x: order.get(x.severity, 3)):
        label = c(f.severity, _LABEL[f.severity].ljust(5))
        print(f"  {label}  [{f.check}] {f.message}")
    print()
    summary = f"{counts['errors']} error(s), {counts['warnings']} warning(s)."
    verdict = "FAIL" if counts["errors"] else "PASS (with warnings)"
    print(f"  {c(ERROR if counts['errors'] else WARN, verdict)}  {summary}")
    print()
