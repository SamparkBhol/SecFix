import os
import json
import html
from datetime import datetime

from . import patch

ORDER = ["critical", "high", "medium", "low", "info"]
BADGE = {
    "critical": "#b91c1c",
    "high": "#c2410c",
    "medium": "#b45309",
    "low": "#2563eb",
    "info": "#4b5563",
}


def summarize(results):
    s = {k: 0 for k in ORDER}
    tot = 0
    withf = 0
    fixed = 0
    for r in results:
        if r.vulns:
            withf += 1
        if r.fixed:
            fixed += 1
        for v in r.vulns:
            tot += 1
            sev = str(v.get("severity", "info")).lower()
            s[sev if sev in s else "info"] += 1
    return {"files": len(results), "with_findings": withf, "total": tot, "fixed": fixed, "sev": s}


def _lines(v):
    ln = v.get("lines")
    if isinstance(ln, list) and ln:
        a = ln[0]
        b = ln[-1] if len(ln) > 1 else ln[0]
        return f"{a}" if a == b else f"{a}-{b}"
    if isinstance(ln, int):
        return str(ln)
    return "?"


def _asstr(x):
    if not x:
        return []
    if isinstance(x, (list, tuple)):
        return [str(i).strip() for i in x if str(i).strip()]
    s = str(x).strip()
    return [s] if s else []


def _tag(v, sep=" · "):
    parts = []
    for k in ("cwe", "owasp"):
        parts += _asstr(v.get(k))
    return sep.join(parts)


def _status(r, amp="&"):
    if not r.vulns:
        return "clean"
    if r.fixed:
        return f"fixed {amp} verified" if r.verified else "fixed"
    return "findings open"


def _refs(results):
    seen = []
    for r in results:
        for v in r.vulns:
            for key in ("cwe", "owasp"):
                for x in _asstr(v.get(key)):
                    if x not in seen:
                        seen.append(x)
    return sorted(seen)


def emit(results, outdir, fmts):
    os.makedirs(outdir, exist_ok=True)
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    written = []
    if "md" in fmts:
        p = os.path.join(outdir, "report.md")
        with open(p, "w", encoding="utf-8") as fh:
            fh.write(md(results, ts))
        written.append(p)
    if "html" in fmts:
        p = os.path.join(outdir, "report.html")
        with open(p, "w", encoding="utf-8") as fh:
            fh.write(html_doc(results, ts))
        written.append(p)
    if "pdf" in fmts:
        p = os.path.join(outdir, "report.pdf")
        try:
            pdf(results, ts, p)
            written.append(p)
        except Exception as e:
            written.append(f"(pdf skipped: {e})")
    if "sarif" in fmts:
        p = os.path.join(outdir, "report.sarif")
        with open(p, "w", encoding="utf-8") as fh:
            json.dump(sarif(results), fh, indent=2)
        written.append(p)
    return written


LEVEL = {"critical": "error", "high": "error", "medium": "warning", "low": "note", "info": "note"}


def _region(v):
    ln = v.get("lines")
    a = b = 1
    if isinstance(ln, list) and ln and isinstance(ln[0], int):
        a = max(1, ln[0])
        b = max(a, ln[-1] if isinstance(ln[-1], int) else a)
    elif isinstance(ln, int):
        a = b = max(1, ln)
    return {"startLine": a, "endLine": b}


def sarif(results):
    rules = {}
    out = []
    for r in results:
        uri = r.path.replace("\\", "/").lstrip("/")
        for v in r.vulns:
            sev = str(v.get("severity", "info")).lower()
            rid = (_asstr(v.get("cwe")) or [str(v.get("title", "finding"))])[0]
            if rid not in rules:
                rules[rid] = {"id": rid, "name": str(v.get("title", rid)),
                              "shortDescription": {"text": str(v.get("title", rid))}}
            out.append({
                "ruleId": rid,
                "level": LEVEL.get(sev, "note"),
                "message": {"text": str(v.get("desc", v.get("title", "")))},
                "locations": [{"physicalLocation": {
                    "artifactLocation": {"uri": uri},
                    "region": _region(v),
                }}],
                "properties": {"severity": sev, "tags": _asstr(v.get("cwe")) + _asstr(v.get("owasp")),
                               "fixed": bool(r.fixed)},
            })
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "secfix", "version": "1.0.0",
                                "rules": list(rules.values())}},
            "results": out,
        }],
    }


def md(results, ts):
    s = summarize(results)
    o = []
    o.append("# Secure Coding Assessment")
    o.append("")
    o.append(f"Generated {ts}")
    o.append("")
    o.append("## Summary")
    o.append("")
    o.append(f"- Files scanned: {s['files']}")
    o.append(f"- Files with findings: {s['with_findings']}")
    o.append(f"- Total findings: {s['total']}")
    o.append(f"- Fixed and verified: {s['fixed']}")
    o.append("- Severity: " + ", ".join(f"{k} {s['sev'].get(k,0)}" for k in ORDER))
    o.append("")
    for r in results:
        o.append(f"## {r.path}")
        st = _status(r)
        o.append(f"language: {r.lang or 'unknown'} — status: {st}")
        if r.error:
            o.append(f"> error: {r.error}")
        o.append("")
        if not r.vulns:
            o.append("No vulnerabilities identified.")
            o.append("")
            continue
        for v in r.vulns:
            sev = str(v.get("severity", "info")).lower()
            o.append(f"### [{sev.upper()}] {v.get('title','(untitled)')}")
            tag = _tag(v)
            o.append(f"lines {_lines(v)}" + (f" — {tag}" if tag else ""))
            o.append("")
            o.append(f"**Vulnerability.** {v.get('desc','')}")
            o.append(f"**Risk & impact.** {v.get('impact','')}")
            o.append(f"**Remediation.** {v.get('fix','')}")
            sn = str(v.get("snippet", "")).strip()
            if sn:
                o.append("")
                o.append("```")
                o.append(sn)
                o.append("```")
            o.append("")
        if r.patched:
            o.append("### Patch")
            vr = "not run" if not r.verified else ("resolved" if r.fixed else "unresolved")
            o.append(f"syntax: {'ok' if r.syntax_ok else 'FAILED'} ({r.syntax_msg}) — verification: {vr}")
            if r.notes:
                o.append(f"changes: {r.notes}")
            if r.remaining:
                o.append(f"still open after patch: {len(r.remaining)}")
            if r.regress:
                o.append(f"regression check: {r.regress}")
            o.append("")
            o.append("```diff")
            o.append(patch.diff(r.src, r.patched, r.path).rstrip())
            o.append("```")
            o.append("")
    refs = _refs(results)
    if refs:
        o.append("## References")
        o.append("")
        for x in refs:
            o.append(f"- {x}")
        o.append("")
    return "\n".join(o)


def html_doc(results, ts):
    s = summarize(results)
    e = html.escape
    css = (
        "body{font:15px/1.5 -apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;"
        "max-width:960px;margin:2rem auto;padding:0 1rem;color:#111}"
        "h1{margin-bottom:.2rem}h2{border-bottom:1px solid #ddd;padding-bottom:.3rem;margin-top:2rem}"
        ".sub{color:#666}.sev{display:inline-block;color:#fff;border-radius:4px;padding:1px 8px;font-size:12px;font-weight:600}"
        ".card{border:1px solid #e5e7eb;border-radius:8px;padding:1rem;margin:1rem 0}"
        "pre{background:#0d1117;color:#e6edf3;padding:1rem;border-radius:6px;overflow:auto;font-size:13px}"
        "pre.diff .a{color:#f85149}pre.diff .d{color:#3fb950}pre.diff .h{color:#a5a5ff}"
        ".pill{display:inline-block;background:#f3f4f6;border-radius:12px;padding:2px 10px;margin:2px;font-size:13px}"
        ".ok{color:#15803d;font-weight:600}.bad{color:#b91c1c;font-weight:600}code{background:#f3f4f6;padding:1px 4px;border-radius:3px}"
    )
    o = [f"<style>{css}</style>"]
    o.append("<h1>Secure Coding Assessment</h1>")
    o.append(f"<div class='sub'>Generated {e(ts)}</div>")
    o.append("<h2>Summary</h2><div>")
    o.append(f"<span class='pill'>Files: {s['files']}</span>")
    o.append(f"<span class='pill'>With findings: {s['with_findings']}</span>")
    o.append(f"<span class='pill'>Total: {s['total']}</span>")
    o.append(f"<span class='pill'>Fixed &amp; verified: {s['fixed']}</span>")
    for k in ORDER:
        if s["sev"].get(k):
            o.append(f"<span class='sev' style='background:{BADGE[k]}'>{k} {s['sev'][k]}</span> ")
    o.append("</div>")
    for r in results:
        o.append(f"<h2>{e(r.path)}</h2>")
        st = _status(r, "&amp;")
        o.append(f"<div class='sub'>language: {e(r.lang or 'unknown')} — status: {st}</div>")
        if r.error:
            o.append(f"<div class='bad'>error: {e(r.error)}</div>")
        if not r.vulns:
            o.append("<p>No vulnerabilities identified.</p>")
            continue
        for v in r.vulns:
            sev = str(v.get("severity", "info")).lower()
            o.append("<div class='card'>")
            o.append(f"<span class='sev' style='background:{BADGE.get(sev,'#4b5563')}'>{e(sev)}</span> ")
            o.append(f"<b>{e(str(v.get('title','(untitled)')))}</b>")
            tag = _tag(v)
            o.append(f"<div class='sub'>lines {e(_lines(v))}" + (f" — {e(tag)}" if tag else "") + "</div>")
            o.append(f"<p><b>Vulnerability.</b> {e(str(v.get('desc','')))}</p>")
            o.append(f"<p><b>Risk &amp; impact.</b> {e(str(v.get('impact','')))}</p>")
            o.append(f"<p><b>Remediation.</b> {e(str(v.get('fix','')))}</p>")
            sn = str(v.get("snippet", "")).strip()
            if sn:
                o.append(f"<pre>{e(sn)}</pre>")
            o.append("</div>")
        if r.patched:
            vr = "not run" if not r.verified else ("resolved" if r.fixed else "unresolved")
            cls = "ok" if r.fixed else "bad"
            o.append("<h3>Patch</h3>")
            o.append(
                f"<div>syntax: <span class='{'ok' if r.syntax_ok else 'bad'}'>"
                f"{'ok' if r.syntax_ok else 'FAILED'}</span> ({e(r.syntax_msg)}) — "
                f"verification: <span class='{cls}'>{vr}</span></div>"
            )
            if r.notes:
                o.append(f"<div class='sub'>changes: {e(r.notes)}</div>")
            if r.regress:
                o.append(f"<div class='sub'>regression check: {e(r.regress)}</div>")
            o.append("<pre class='diff'>" + _diff_html(r) + "</pre>")
    refs = _refs(results)
    if refs:
        o.append("<h2>References</h2><div>")
        for x in refs:
            o.append(f"<span class='pill'>{e(x)}</span>")
        o.append("</div>")
    return "<!doctype html><meta charset='utf-8'><title>Secure Coding Assessment</title>" + "".join(o)


def _diff_html(r):
    out = []
    for ln in patch.diff(r.src, r.patched, r.path).splitlines():
        t = html.escape(ln)
        if ln.startswith("+"):
            out.append(f"<span class='d'>{t}</span>")
        elif ln.startswith("-"):
            out.append(f"<span class='a'>{t}</span>")
        elif ln.startswith("@@"):
            out.append(f"<span class='h'>{t}</span>")
        else:
            out.append(t)
    return "\n".join(out)


def _lat(x):
    return str(x).encode("latin-1", "replace").decode("latin-1")


def pdf(results, ts, path):
    from fpdf import FPDF

    s = summarize(results)
    d = FPDF()
    d.set_auto_page_break(True, 15)
    d.add_page()

    def w(txt, h=5, font="Helvetica", style="", size=10, grey=False):
        d.set_font(font, style, size)
        d.set_text_color(110 if grey else 0)
        d.multi_cell(0, h, _lat(txt), new_x="LMARGIN", new_y="NEXT")

    w("Secure Coding Assessment", 10, style="B", size=18)
    w("Generated " + ts, 6, grey=True)
    d.ln(2)
    w("Summary", 8, style="B", size=13)
    w(
        f"Files scanned: {s['files']}   Files with findings: {s['with_findings']}   "
        f"Total findings: {s['total']}   Fixed & verified: {s['fixed']}",
        6, size=11,
    )
    w("Severity: " + ", ".join(f"{k} {s['sev'].get(k, 0)}" for k in ORDER), 6, size=11)
    for r in results:
        d.ln(2)
        w(r.path, 7, style="B", size=13)
        st = _status(r)
        w(f"language: {r.lang or 'unknown'} - status: {st}", grey=True)
        if not r.vulns:
            w("No vulnerabilities identified.")
            continue
        for v in r.vulns:
            sev = str(v.get("severity", "info")).lower()
            w(f"[{sev.upper()}] {v.get('title', '(untitled)')}", 6, style="B", size=11)
            tag = _tag(v, " / ")
            w(f"lines {_lines(v)}" + (f" - {tag}" if tag else ""), grey=True)
            for lab, key in (("Vulnerability", "desc"), ("Risk & impact", "impact"), ("Remediation", "fix")):
                w(f"{lab}: {v.get(key, '')}")
            d.ln(1)
        if r.patched:
            vr = "not run" if not r.verified else ("resolved" if r.fixed else "unresolved")
            w("Patch", 6, style="B", size=11)
            w(f"syntax: {'ok' if r.syntax_ok else 'FAILED'} ({r.syntax_msg}) - verification: {vr}")
            if r.notes:
                w("changes: " + r.notes)
            for ln in patch.diff(r.src, r.patched, r.path).splitlines():
                w(ln[:110], 4, font="Courier", size=8)
    refs = _refs(results)
    if refs:
        d.ln(2)
        w("References", 7, style="B", size=13)
        for x in refs:
            w("- " + x)
    d.output(path)
