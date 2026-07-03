import argparse
import json
import os
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed

from .config import load
from .llm import LLM
from .agent import Agent, SEV
from . import scan, patch, report


def log(m):
    print(m, file=sys.stderr, flush=True)


def _slim(r):
    return {
        "path": r.path,
        "lang": r.lang,
        "findings": r.vulns,
        "fixed": r.fixed,
        "verified": r.verified,
        "syntax_ok": r.syntax_ok,
        "remaining": r.remaining,
        "cached": r.cached,
        "error": r.error,
    }


def build_parser():
    ap = argparse.ArgumentParser(
        prog="secfix",
        description="autonomous secure coding assistant: finds vulnerabilities and applies verified fixes",
    )
    ap.add_argument("paths", nargs="+", help="files or directories to scan")
    ap.add_argument("-w", "--apply", action="store_true", help="write fixes back to disk (keeps .bak)")
    ap.add_argument("-y", "--yes", action="store_true", help="skip the confirmation prompt when applying")
    ap.add_argument("-o", "--out", default="report", help="report output directory")
    ap.add_argument("-f", "--format", default="md,html", help="report formats: md,html,pdf,sarif")
    ap.add_argument("--ext", help="restrict to these extensions, e.g. .py,.js")
    ap.add_argument("--workers", type=int, help="parallel workers")
    ap.add_argument("--attempts", type=int, help="max patch/verify refinement rounds")
    ap.add_argument("--max-chars", type=int, dest="max_chars", help="chunk size for large files")
    ap.add_argument("--model", help="override the model name")
    ap.add_argument("--cache", help="reuse analysis for unchanged files from this directory")
    ap.add_argument("--context", action="store_true",
                    help="build a cross-file vector index and feed related code as context")
    ap.add_argument("--embed-model", dest="embed_model",
                    help="embedding model for --context (e.g. nomic-embed-text, text-embedding-3-small)")
    ap.add_argument("--fail-on", dest="fail_on", default="high",
                    choices=["critical", "high", "medium", "low"],
                    help="exit non-zero if an unfixed finding at or above this severity remains")
    ap.add_argument("--no-verify", action="store_true", help="skip the self-verification pass")
    ap.add_argument("--json", action="store_true", help="print machine-readable results to stdout")
    return ap


def main(argv=None):
    a = build_parser().parse_args(argv)
    cfg = load()
    if a.workers:
        cfg.workers = a.workers
    if a.attempts:
        cfg.attempts = a.attempts
    if a.max_chars:
        cfg.max_chars = a.max_chars
    if a.model:
        cfg.model = a.model
    if a.cache:
        cfg.cache = a.cache
    if a.context:
        cfg.context = True
    if a.embed_model:
        cfg.embed_model = a.embed_model
    if a.no_verify:
        cfg.verify = False

    exts = None
    if a.ext:
        exts = {(x if x.startswith(".") else "." + x).lower() for x in a.ext.split(",") if x}

    files = scan.discover(a.paths, exts)
    if not files:
        log("no source files found")
        return 2
    if not cfg.key and "api.openai.com" in cfg.base_url:
        log("warning: LLM_API_KEY is not set; requests to the default endpoint will fail")

    idx = None
    if cfg.context:
        from . import index
        idx = index.Index()
        if idx.build(cfg, files):
            log(f"cross-file context: indexed {len(idx.meta)} symbol(s)")
        else:
            idx = None
            log("cross-file context disabled: endpoint returned no embeddings (set --embed-model?)")

    llm = LLM(cfg)
    ag = Agent(llm, cfg, idx)
    log(f"scanning {len(files)} file(s) with {cfg.workers} worker(s), model {cfg.model}")
    results = []
    dropped = 0
    with ThreadPoolExecutor(max_workers=max(1, cfg.workers)) as ex:
        fut = {ex.submit(ag.run, f): f for f in files}
        for ft in as_completed(fut):
            f = fut[ft]
            try:
                r = ft.result()
            except Exception as e:
                log(f"  failed {f}: {e}")
                dropped += 1
                continue
            results.append(r)
            tail = " [fixed]" if r.fixed else (" [open]" if r.vulns else "")
            if getattr(r, "cached", False):
                tail += " [cached]"
            log(f"  {f}: {len(r.vulns)} finding(s){tail}")
    llm.close()
    results.sort(key=lambda r: r.path)

    if a.json:
        print(json.dumps([_slim(r) for r in results], indent=2))

    fmts = {x.strip() for x in a.format.split(",") if x.strip()}
    for w in report.emit(results, a.out, fmts):
        log(f"report: {w}")

    if a.apply:
        _apply(results, a.yes)

    lim = SEV.get(a.fail_on, 1)
    bad = sum(
        1
        for r in results
        if not r.fixed
        for v in r.vulns
        if SEV.get(str(v.get("severity", "")).strip().lower(), 5) <= lim
    )
    errs = dropped + sum(1 for r in results if r.error)
    if bad:
        return 1
    if errs:
        return 2
    return 0


def _apply(results, yes):
    cand = [r for r in results if r.patched and r.fixed]
    if not cand:
        log("nothing to apply")
        return
    if not yes:
        try:
            ans = input(f"apply {len(cand)} verified patch(es) in place? [y/N] ")
        except EOFError:
            ans = ""
        if ans.strip().lower() not in ("y", "yes"):
            log("apply aborted")
            return
    for r in cand:
        patch.write_out(r.path, r.patched)
        log(f"patched {r.path} (backup at {r.path}.bak)")
