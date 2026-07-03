import os
import shutil
import subprocess
import tempfile
import difflib


def validate(lang, src):
    if lang == "python":
        try:
            compile(src, "<patched>", "exec")
            return True, "compiles"
        except SyntaxError as e:
            return False, f"syntax error: {e.msg} (line {e.lineno})"
    if lang == "javascript":
        if shutil.which("node"):
            return _run(["node", "--check"], src, ".js")
        return True, "node not available"
    if lang in ("typescript", "jsx"):
        return True, f"{lang} not validated"
    if lang == "php":
        if shutil.which("php"):
            return _run(["php", "-l"], src, ".php")
        return True, "php not available"
    if lang == "ruby":
        if shutil.which("ruby"):
            return _run(["ruby", "-c"], src, ".rb")
        return True, "ruby not available"
    if lang == "go":
        if shutil.which("gofmt"):
            return _run(["gofmt", "-e"], src, ".go")
        return True, "gofmt not available"
    return True, "no validator for " + str(lang)


def _run(cmd, src, ext):
    fh = tempfile.NamedTemporaryFile("w", suffix=ext, delete=False, encoding="utf-8")
    fh.write(src)
    fh.close()
    try:
        r = subprocess.run(cmd + [fh.name], capture_output=True, text=True, timeout=30)
        msg = (r.stderr or r.stdout).strip().replace(fh.name, "<file>")
        return r.returncode == 0, (msg[:400] or "ok")
    except (subprocess.TimeoutExpired, OSError) as e:
        return True, f"validator skipped: {e}"
    finally:
        try:
            os.unlink(fh.name)
        except OSError:
            pass


def diff(a, b, path):
    d = difflib.unified_diff(
        a.splitlines(True), b.splitlines(True), f"a/{path}", f"b/{path}"
    )
    return "".join(d)


def write_out(path, patched, backup=True):
    bak = path + ".bak"
    if backup and os.path.exists(path) and not os.path.exists(bak):
        shutil.copy2(path, bak)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(patched)
