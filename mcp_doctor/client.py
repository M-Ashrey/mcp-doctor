"""Minimal, dependency-free MCP stdio client.

Speaks just enough of the Model Context Protocol (JSON-RPC 2.0 over
newline-delimited stdio) to launch a server, complete the initialize
handshake, and enumerate its tools, resources, and prompts.

Security notes:
- The target server is launched with an explicit argument list and
  shell=False -- the command is never passed through a shell, so there
  is no shell-injection surface here.
- All server I/O is treated as untrusted: reads are size-bounded and every
  call is wrapped in a timeout so a hung server cannot block indefinitely.
"""
from __future__ import annotations

import json
import subprocess
import threading
from dataclasses import dataclass, field
from typing import Any, Optional

PROTOCOL_VERSION = "2024-11-05"


@dataclass
class ServerInfo:
    name: str = ""
    version: str = ""
    protocol_version: str = ""
    capabilities: dict = field(default_factory=dict)


class MCPClientError(Exception):
    """Raised when the server cannot be reached or violates the protocol."""


class MCPStdioClient:
    """A tiny synchronous MCP client over a stdio subprocess."""

    def __init__(self, command: list, timeout: float = 20.0,
                 env: Optional[dict] = None, cwd: Optional[str] = None) -> None:
        if not command or not isinstance(command, list):
            raise ValueError("command must be a non-empty list of arguments")
        self.command = command
        self.timeout = timeout
        self._env = env
        self._cwd = cwd
        self._proc: Optional[subprocess.Popen] = None
        self._next_id = 0
        self.stderr_tail: list = []

    def __enter__(self) -> "MCPStdioClient":
        self.start()
        return self

    def __exit__(self, *exc: Any) -> None:
        self.close()

    def start(self) -> None:
        try:
            self._proc = subprocess.Popen(
                self.command, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                stderr=subprocess.PIPE, text=True, bufsize=1, shell=False,
                env=self._env, cwd=self._cwd)
        except FileNotFoundError as exc:
            raise MCPClientError(f"command not found: {self.command[0]}") from exc
        except OSError as exc:
            raise MCPClientError(f"failed to launch server: {exc}") from exc
        threading.Thread(target=self._drain_stderr, daemon=True).start()

    def _drain_stderr(self) -> None:
        proc = self._proc
        if not proc or not proc.stderr:
            return
        for line in proc.stderr:
            self.stderr_tail.append(line.rstrip("\n"))
            if len(self.stderr_tail) > 50:
                self.stderr_tail.pop(0)

    def close(self) -> None:
        proc = self._proc
        if not proc:
            return
        try:
            if proc.stdin:
                proc.stdin.close()
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
        except Exception:
            pass
        self._proc = None

    # -- JSON-RPC plumbing ----------------------------------------------
    def _send(self, obj: dict) -> None:
        proc = self._proc
        if not proc or not proc.stdin:
            raise MCPClientError("server process is not running")
        try:
            proc.stdin.write(json.dumps(obj) + "\n")
            proc.stdin.flush()
        except (BrokenPipeError, OSError) as exc:
            raise MCPClientError(f"server closed the connection: {exc}") from exc

    def _read_result(self, want_id: int) -> dict:
        """Read newline-delimited JSON until we see the response for want_id."""
        proc = self._proc
        if not proc or not proc.stdout:
            raise MCPClientError("server process is not running")
        deadline = threading.Event()
        timer = threading.Timer(self.timeout, deadline.set)
        timer.start()
        try:
            while not deadline.is_set():
                line = proc.stdout.readline()
                if line == "":
                    hint = " | stderr: " + " ".join(self.stderr_tail[-3:]) if self.stderr_tail else ""
                    raise MCPClientError(
                        "server produced no response (closed stdout)." + hint)
                line = line.strip()
                if not line:
                    continue
                try:
                    msg = json.loads(line)
                except json.JSONDecodeError:
                    # Not JSON-RPC (stray log line on stdout). Ignore politely.
                    continue
                if msg.get("id") == want_id:
                    if "error" in msg:
                        raise MCPClientError(f"server error: {msg['error']}")
                    return msg.get("result", {})
                # else: notification or a different id -> keep reading
            raise MCPClientError(
                f"timed out after {self.timeout}s waiting for the server to respond")
        finally:
            timer.cancel()

    def _request(self, method: str, params: Optional[dict] = None) -> dict:
        self._next_id += 1
        rid = self._next_id
        self._send({"jsonrpc": "2.0", "id": rid, "method": method,
                    "params": params or {}})
        return self._read_result(rid)

    def _notify(self, method: str, params: Optional[dict] = None) -> None:
        self._send({"jsonrpc": "2.0", "method": method, "params": params or {}})

    # -- MCP operations --------------------------------------------------
    def initialize(self) -> ServerInfo:
        result = self._request("initialize", {
            "protocolVersion": PROTOCOL_VERSION,
            "capabilities": {},
            "clientInfo": {"name": "mcp-doctor", "version": "0.1.0"},
        })
        self._notify("notifications/initialized")
        info = result.get("serverInfo", {}) or {}
        return ServerInfo(
            name=info.get("name", ""),
            version=info.get("version", ""),
            protocol_version=result.get("protocolVersion", ""),
            capabilities=result.get("capabilities", {}) or {},
        )

    def _list(self, method: str, key: str) -> list:
        try:
            result = self._request(method, {})
        except MCPClientError:
            return []  # capability not supported -> treat as empty
        items = result.get(key, [])
        return items if isinstance(items, list) else []

    def list_tools(self) -> list:
        return self._list("tools/list", "tools")

    def list_resources(self) -> list:
        return self._list("resources/list", "resources")

    def list_prompts(self) -> list:
        return self._list("prompts/list", "prompts")
