# Security Policy

## Reporting a Vulnerability

If you find a security vulnerability in `mcp-doctor`, please report it privately rather than opening a public issue.

- **Preferred:** open the repo's [Security tab -> Report a vulnerability](https://github.com/M-Ashrey/mcp-doctor/security/advisories/new) (GitHub private advisory).
- **Alternative:** email m.ashrey122@gmail.com with subject `SECURITY: mcp-doctor`.

Please include a description of the issue, steps to reproduce (a minimal example is ideal), and the potential impact. A suggested fix is welcome but not required.

This is a solo-maintained open-source project — there's no formal SLA, but security reports are treated as priority and acknowledged as soon as I see them, typically within a few days.

## Supported Versions

Only the latest release on PyPI and the `main` branch are supported. There are no LTS branches at this stage.

## Scope

`mcp-doctor` is a static/dynamic analysis CLI: it launches the MCP server you point it at (as an argument list, never through a shell) and inspects its handshake and declared tools/resources/prompts. It does not execute anything the *target server* returns to it. If you find a way for a scanned server's output to make `mcp-doctor` itself execute unintended code, that's a high-priority report.
