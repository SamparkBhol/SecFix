# secfix

An autonomous secure-coding agent. It reads source code, reasons about it with a
language model to find real vulnerabilities, rewrites the affected files to fix
them, and then independently re-audits its own patch to confirm the issue is gone
and the code still parses. Detection and remediation are driven entirely by model
reasoning — there are no built-in vulnerability signatures or rule tables.

## How it works

For every file the agent runs a closed loop:

1. **Perceive** — detect language, read the file, split oversized files into
   overlapping windows so large sources stay within context.
2. **Reason** — the model reviews each window and returns findings with line
   numbers, CWE / OWASP mapping, severity, impact and remediation.
3. **Act** — the model rewrites the whole file to fix the confirmed findings
   while preserving signatures and behaviour.
4. **Verify** — the patch is parsed with the language's own toolchain
   (functionality signal) and re-audited by the model as an independent reviewer.
   If anything is still open the loop feeds that back and refines the patch, up
   to `attempts` rounds.

Only patches that both parse and pass verification are marked fixed. Files are
processed in parallel.

## Install

```
pip install -r requirements.txt        # run via: python -m secfix ...
```

or install it as a package to get the `secfix`, `secfix-web` and `secfix-mcp`
commands on your PATH:

```
pip install .                          # core
pip install ".[context,mcp]"           # + cross-file vector index + MCP server
```

The core needs only `httpx` and `fpdf2`. The cross-file index adds `numpy`; the
MCP server adds `mcp`. Both features are optional and degrade gracefully.

## Configure

The agent talks to any OpenAI-compatible chat-completions endpoint (hosted or
self-hosted). Copy `.env.example` to `.env` and set:

```
LLM_BASE_URL   endpoint base, e.g. https://api.openai.com/v1 or http://localhost:11434/v1
LLM_API_KEY    key for that endpoint
LLM_MODEL      model name
```

### Free and local models

`.env.example` ships ready-to-use presets. No paid account is required:

- **Ollama** (default, no key, no signup): install from https://ollama.com, run
  `ollama pull qwen2.5-coder:7b`, and it works offline out of the box.
- **Groq**, **OpenRouter** (free models), **Google Gemini** — free tiers with an
  OpenAI-compatible endpoint. Uncomment the preset and paste your own free key.

## Desktop UI

A Windows XP-style desktop app that exposes the whole workflow in the browser:

```
python -m secfix.web            # then open http://127.0.0.1:8000
```

Add files by dropping them in, browsing, or `+ New file` (each with an inline
source editor); set the options that mirror the CLI (Verify, Attempts, Cross-file
context, Fail-on); then Scan all. Files land in a list with their status; the
detail pane shows Source, Findings (severity, CWE/OWASP, risk, remediation) and
Patch (a diff with a Download fixed file button). The Report buttons export the
run as Markdown, HTML, PDF or SARIF. It uses the same `.env` as the CLI and adds
no dependencies (standard-library server).

## Use

```
python -m secfix samples/                       # scan a tree, write report/
python -m secfix samples/login.py -f md,html,pdf
python -m secfix src/ --ext .py,.js --workers 16
python -m secfix app.py --apply                 # write verified fixes back (.bak kept)
python -m secfix src/ -f sarif --cache .sfcache # SARIF for CI, reuse unchanged files
python -m secfix src/ --json > findings.json    # machine-readable output
```

By default nothing on disk is changed: the agent produces a report and patched
content in memory. `--apply` writes fixes back, keeps a `.bak`, and — unless
`--yes` is given — only applies patches that passed verification and asks for
confirmation first. The process exits non-zero when unresolved findings at or
above `--fail-on` remain, which makes it usable as a CI gate.

### CI integration

Emit SARIF (`-f sarif` writes `report.sarif`) to feed GitHub code scanning,
Azure DevOps, or any SARIF viewer. Point `--cache` at a directory to skip
re-analyzing files whose contents have not changed since the last run — the
practical way to keep large or monorepo scans, and PR re-scans, cheap. Use
`--fail-on` to control the severity that trips a non-zero exit.

### Options

```
-w, --apply        write fixes in place (keeps .bak)
-y, --yes          apply without the confirmation prompt
-o, --out DIR      report directory (default: report)
-f, --format       md,html,pdf,sarif (default: md,html)
    --ext          restrict to extensions, e.g. .py,.js
    --workers N    parallel files
    --attempts N   patch/verify refinement rounds
    --max-chars N  window size for large files
    --model NAME   override the model
    --cache DIR    reuse analysis for unchanged files (content-hash keyed)
    --context      build a cross-file vector index and feed related code as context
    --embed-model  embedding model for --context (e.g. nomic-embed-text)
    --fail-on SEV  exit non-zero at/above this severity (default: high)
    --no-verify    skip self-verification
    --json         print results to stdout
```

## Cross-file analysis (vector index)

By default each file is analyzed on its own. `--context` builds an in-memory
vector index of the codebase's functions and classes (embedded through the same
endpoint's `/embeddings` API), and for each file being scanned it retrieves the
most similar code from *other* files and includes it as read-only context. This
gives the model the definition of a helper called across a module boundary — the
information needed to reason about a source in one file reaching a sink in
another.

```
pip install ".[context]"
python -m secfix src/ --context --embed-model nomic-embed-text
```

Needs an endpoint that exposes embeddings (OpenAI, Ollama, Gemini). If the
endpoint has no embeddings API the feature disables itself and the normal
per-file scan continues.

## MCP server

SecFix can run as an [MCP](https://modelcontextprotocol.io) server so any MCP
client (an IDE, a desktop assistant, a CI agent) can call it as a tool:

```
pip install ".[mcp]"
python -m secfix.mcp_server        # stdio transport
```

Exposes two tools: `scan_code(code, lang)` and `scan_file(path)`, each returning
findings, a patched version, the verification result and a diff.

## Layout

```
secfix/
  config.py    environment / .env configuration
  prompts.py   review, remediation and verification prompts
  llm.py       OpenAI-compatible client with retries and JSON recovery
  scan.py      discovery, language detection, windowing
  agent.py     the perceive/reason/act/verify loop
  patch.py     syntax validation, diffing, safe write-back
  cache.py     content-hash cache so unchanged files skip the model
  index.py     cross-file vector index (embeddings + cosine retrieval)
  report.py    Markdown / HTML / PDF / SARIF reporting
  cli.py       argument parsing and parallel orchestration
  web.py       small Windows XP-style desktop UI (stdlib http.server)
  mcp_server.py  Model Context Protocol server (scan_code / scan_file tools)
samples/       deliberately vulnerable files for a demo run
tests/         offline harness with a mock endpoint (no key needed)
pyproject.toml installable package with secfix / secfix-web / secfix-mcp commands
```

## Scaling

Files are windowed and scanned concurrently, so throughput grows with `--workers`
and the endpoint's rate limit. For very large trees, point it at a directory and
narrow with `--ext`; findings from overlapping windows are de-duplicated per
file. Language toolchains used for the functionality check are optional — a
missing one degrades to "not validated" rather than failing the run.

## Tests

```
python -m unittest discover -s tests -v
```

The suite spins up a local mock endpoint and drives the whole loop — analyze,
patch, verify, report — without any network access or API key.
