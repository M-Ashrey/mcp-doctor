# mcp-doctor

**Point it at any MCP server. It tells you what's broken, bloated, or insecure — in your terminal and in CI.**

Building an MCP server is easy. Knowing whether it actually *works*, won't confuse the model, and isn't a security hole is the hard part. The official Inspector is a GUI — great for poking around, awkward for complex servers and useless in a CI pipeline. `mcp-doctor` is the command-line counterpart: it launches your server, runs the full handshake, introspects everything it exposes, and reports problems with a real exit code.

Zero dependencies. One command.

```bash
pipx install mcp-doctor      # or: pip install mcp-doctor
mcp-doctor -- python -m my_server
```

Everything after `--` is how you launch your server (stdio). It's run as an argument list, never through a shell.

## What it checks

**Health**
- Server actually starts and completes the `initialize` handshake (catches the classic "it just outputs nothing").
- Enumerates tools, resources, and prompts so you see the real surface.

**Quality / model-friendliness**
- **Tool bloat** — flags when you expose so many tools that model selection accuracy degrades (it drops off a cliff past a couple dozen).
- Missing, thin, oversized, or duplicate tool descriptions.
- Missing or weak input schemas.

**Security**
- **Prompt injection** — override-style language ("ignore previous instructions…") hidden in tool/prompt descriptions that gets fed straight to the model.
- **Dangerous surface** — tools/parameters that look like they shell out or `eval`, flagged for review.
- **Secret leakage** — API keys or private keys accidentally embedded in the server's metadata.

## Example

```
$ mcp-doctor -- python -m my_server

  mcp-doctor  ->  my-server 0.1.0
  protocol 2024-11-05  |  27 tools, 3 resources, 0 prompts

  ERROR  [prompt-injection] A tool description contains override-style language...
  ERROR  [missing-description] Tool 'helper' has no description...
  WARN   [tool-bloat] 27 tools exposed. Selection accuracy starts to degrade past ~20...
  WARN   [dangerous-tool] Tool 'run_shell' looks like it executes commands...

  FAIL  2 error(s), 2 warning(s).
```

## Use it in CI

`mcp-doctor` exits `0` when clean, `1` when it finds an error-level issue — so it drops straight into a pipeline:

```yaml
- run: pipx install mcp-doctor
- run: mcp-doctor -- python -m my_server
```

Add `--json` for machine-readable output:

```bash
mcp-doctor --json -- node build/index.js
```

## Options

| flag | meaning |
|---|---|
| `--json` | emit findings as JSON |
| `--timeout N` | seconds to wait for each server response (default 20) |
| `--no-color` | disable ANSI color |

## Why the checks are what they are

Every check maps to a real, reported failure mode when running MCP servers with Claude and other agents: servers that silently produce nothing, tool lists so large the model picks wrong, descriptions that quietly inject instructions, and secrets that leak through metadata. `mcp-doctor` is deliberately conservative — it tells you *what* looks wrong and *why*, and leaves the judgment call to you.

## Development

```bash
git clone https://github.com/M-Ashrey/mcp-doctor && cd mcp-doctor
pip install -e ".[dev]"
python -m unittest discover -s tests -v
```

Part of a small family of dependency-light MCP/agent tools:
[memory-mcp](https://github.com/M-Ashrey/memory-mcp) · [promptlint](https://github.com/M-Ashrey/promptlint) · [claude-mcp-starter-kit](https://github.com/M-Ashrey/claude-mcp-starter-kit)

## License

MIT © Mohamed Ashrey
