"""Health, quality, and security checks for an MCP server's surface.

Each check takes the introspected data (tools/resources/prompts) and returns
a list of Findings. Findings have a severity so the CLI can decide the exit
code (any ERROR -> exit 1).

The security checks are deliberately heuristic and conservative: they flag
things a human should look at, and say *why*, rather than claiming certainty.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

ERROR = "error"
WARN = "warn"
INFO = "info"

# Tunable thresholds (documented in the README).
TOOL_BLOAT_WARN = 20          # success rate degrades as tool count climbs
TOOL_BLOAT_ERROR = 40
DESC_MIN_CHARS = 12           # a real description, not "does stuff"
DESC_MAX_CHARS = 1024         # oversized descriptions burn token budget


@dataclass
class Finding:
    severity: str
    check: str
    message: str

    def as_dict(self) -> dict:
        return {"severity": self.severity, "check": self.check,
                "message": self.message}


# Phrases in a tool description that could hijack the model (prompt injection).
_INJECTION_PATTERNS = [
    r"ignore (all |any |the )?(previous|prior|above)",
    r"disregard (the |all )?(previous|prior|above|instructions)",
    r"system prompt",
    r"you are now",
    r"do not tell the user",
    r"regardless of (what|any)",
]
# Handler/parameter naming that suggests shelling out or evaluating code.
_DANGER_NAME = re.compile(
    r"(^|[_\-])(exec|eval|shell|spawn|system|subprocess|run_?command|cmd|"
    r"os_?command|popen)($|[_\-])", re.I)
# Things that look like leaked secrets in descriptions/schemas.
_SECRET_PATTERN = re.compile(
    r"(sk-[A-Za-z0-9]{16,}|ghp_[A-Za-z0-9]{20,}|AKIA[0-9A-Z]{12,}|"
    r"-----BEGIN [A-Z ]*PRIVATE KEY-----|xox[baprs]-[A-Za-z0-9-]{10,})")


def _text_of(tool: dict) -> str:
    return " ".join(str(tool.get(k, "")) for k in ("name", "description"))


def check_tool_bloat(tools: list) -> list:
    n = len(tools)
    if n >= TOOL_BLOAT_ERROR:
        return [Finding(ERROR, "tool-bloat",
                        f"{n} tools exposed. Beyond ~{TOOL_BLOAT_ERROR}, model "
                        "tool-selection accuracy drops sharply. Split into "
                        "focused servers or gate tools behind a router.")]
    if n >= TOOL_BLOAT_WARN:
        return [Finding(WARN, "tool-bloat",
                        f"{n} tools exposed. Selection accuracy starts to "
                        f"degrade past ~{TOOL_BLOAT_WARN}; consider trimming.")]
    return []


def check_descriptions(tools: list) -> list:
    out: list = []
    seen: dict = {}
    for t in tools:
        name = t.get("name", "<unnamed>")
        desc = (t.get("description") or "").strip()
        if not desc:
            out.append(Finding(ERROR, "missing-description",
                               f"Tool '{name}' has no description. The model "
                               "cannot choose it reliably without one."))
        elif len(desc) < DESC_MIN_CHARS:
            out.append(Finding(WARN, "thin-description",
                               f"Tool '{name}' description is very short "
                               f"({len(desc)} chars); be specific about when "
                               "to use it."))
        elif len(desc) > DESC_MAX_CHARS:
            out.append(Finding(WARN, "oversized-description",
                               f"Tool '{name}' description is {len(desc)} chars; "
                               "large descriptions inflate every request's "
                               "token cost."))
        seen.setdefault(name, 0)
        seen[name] += 1
    for name, count in seen.items():
        if count > 1:
            out.append(Finding(ERROR, "duplicate-tool",
                               f"Tool name '{name}' is defined {count} times; "
                               "duplicate names are ambiguous to the model."))
    return out


def check_schemas(tools: list) -> list:
    out: list = []
    for t in tools:
        name = t.get("name", "<unnamed>")
        schema = t.get("inputSchema")
        if schema is None:
            out.append(Finding(WARN, "missing-schema",
                               f"Tool '{name}' declares no inputSchema; clients "
                               "cannot validate arguments before calling it."))
            continue
        if not isinstance(schema, dict) or schema.get("type") != "object":
            out.append(Finding(WARN, "weak-schema",
                               f"Tool '{name}' inputSchema should be a JSON "
                               "Schema object (type: object) for safe arg "
                               "validation."))
    return out


def check_injection(tools: list, prompts: list) -> list:
    """Flag prompt-injection style phrasing embedded in tool/prompt text.

    A malicious or careless description can smuggle instructions to the model
    every time the tool list is loaded. We surface anything that reads like an
    override so a human can judge it.
    """
    out: list = []
    surfaces = [("tool", _text_of(t)) for t in tools]
    surfaces += [("prompt", " ".join(str(p.get(k, "")) for k in
                 ("name", "description"))) for p in prompts]
    for kind, text in surfaces:
        low = text.lower()
        for pat in _INJECTION_PATTERNS:
            if re.search(pat, low):
                snippet = text.strip()[:80]
                out.append(Finding(ERROR, "prompt-injection",
                                   f"A {kind} description contains override-style "
                                   f"language (matched /{pat}/): \"{snippet}...\". "
                                   "This text is fed to the model and can hijack "
                                   "it. Remove instruction-like phrasing."))
                break
    return out


def check_dangerous_surface(tools: list) -> list:
    """Flag tools whose name/params suggest command execution or eval."""
    out: list = []
    for t in tools:
        name = t.get("name", "<unnamed>")
        if _DANGER_NAME.search(name or ""):
            out.append(Finding(WARN, "dangerous-tool",
                               f"Tool '{name}' looks like it executes commands "
                               "or code. Ensure it uses an argument list (never "
                               "a shell string), validates inputs, and is not "
                               "exposed to untrusted callers."))
        schema = t.get("inputSchema") or {}
        props = schema.get("properties", {}) if isinstance(schema, dict) else {}
        for pname in props:
            if _DANGER_NAME.search(str(pname)):
                out.append(Finding(WARN, "dangerous-parameter",
                                   f"Tool '{name}' has a parameter '{pname}' that "
                                   "may carry raw commands/code. Treat it as "
                                   "untrusted and avoid passing it to a shell."))
    return out


def check_secret_leak(tools: list, resources: list, prompts: list,
                      server_info=None) -> list:
    """Flag anything that looks like a leaked credential in the surface."""
    out: list = []
    blobs = []
    for t in tools:
        blobs.append(_text_of(t))
    for r in resources:
        blobs.append(" ".join(str(r.get(k, "")) for k in ("name", "uri", "description")))
    for p in prompts:
        blobs.append(" ".join(str(p.get(k, "")) for k in ("name", "description")))
    for blob in blobs:
        m = _SECRET_PATTERN.search(blob)
        if m:
            out.append(Finding(ERROR, "secret-leak",
                               "A credential-like token appears in the server's "
                               f"public surface ({m.group(0)[:6]}...). Never embed "
                               "secrets in tool/resource metadata."))
    return out


def run_all(server_info, tools: list, resources: list, prompts: list) -> list:
    findings: list = []
    findings += check_tool_bloat(tools)
    findings += check_descriptions(tools)
    findings += check_schemas(tools)
    findings += check_injection(tools, prompts)
    findings += check_dangerous_surface(tools)
    findings += check_secret_leak(tools, resources, prompts, server_info)
    return findings
