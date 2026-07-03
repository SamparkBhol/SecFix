from mcp.server.fastmcp import FastMCP

from .config import load
from .llm import LLM
from .agent import Agent
from . import scan, patch
from .web import run_src

app = FastMCP("secfix")


@app.tool(description=(
    "Scan a source snippet for security vulnerabilities and return a patched version. "
    "Returns findings (title, severity, cwe, owasp, line numbers, desc, impact, fix), the "
    "patched code, whether it was verified as fixed, and a unified diff. lang is one of "
    "python, javascript, jsx, typescript, php, java, ruby, go, c, cpp, csharp."))
def scan_code(code: str, lang: str = "python") -> dict:
    return run_src(code, lang)


@app.tool(description=(
    "Scan a file on disk for security vulnerabilities and return findings, a patched "
    "version, whether it was verified as fixed, and a unified diff."))
def scan_file(path: str) -> dict:
    lang = scan.lang_of(path)
    if not lang:
        return {"error": f"unsupported file type: {path}"}
    cfg = load()
    llm = LLM(cfg)
    ag = Agent(llm, cfg)
    try:
        r = ag.run(path)
    finally:
        llm.close()
    diff = patch.diff(r.src, r.patched, path) if r.patched else ""
    return {"path": r.path, "lang": r.lang, "vulns": r.vulns, "patched": r.patched,
            "notes": r.notes, "fixed": r.fixed, "verified": r.verified,
            "syntax_ok": r.syntax_ok, "diff": diff, "error": r.error}


def main():
    app.run()


if __name__ == "__main__":
    main()
