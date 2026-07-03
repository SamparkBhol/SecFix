import json
import re
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

CAT = {
    "eval(": ("Unsafe eval on input", "CWE-95", "A03:2021-Injection", "critical"),
    "hashlib.md5(": ("Weak password hash", "CWE-327", "A02:2021-Cryptographic Failures", "high"),
    "os.system(": ("OS command injection", "CWE-78", "A03:2021-Injection", "critical"),
}
FIX = {
    "eval(": "int(",
    "hashlib.md5(": "hashlib.sha256(",
    "os.system(": "safe_run(",
}


def _lineno(numbered, tok):
    for ln in numbered.splitlines():
        if tok in ln and "|" in ln:
            try:
                return int(ln.split("|", 1)[0].strip())
            except ValueError:
                pass
    return 1


def _analyze(user):
    vs = []
    for tok, (title, cwe, owasp, sev) in CAT.items():
        if tok in user:
            n = _lineno(user, tok)
            vs.append({
                "title": title, "cwe": cwe, "owasp": owasp, "severity": sev,
                "lines": [n, n], "snippet": tok,
                "desc": f"user input reaches {tok}",
                "impact": "attacker controlled execution",
                "fix": f"replace {tok} with a safe equivalent",
            })
    return {"vulns": vs}


def _patch(user):
    src = user.split("\nfile:\n", 1)[-1]
    for tok, rep in FIX.items():
        src = src.replace(tok, rep)
    return {"patched": src, "notes": "swapped unsafe calls for safe equivalents"}


def _verify(user):
    body = user.split("patched source:\n", 1)[-1]
    body = re.sub(r"^\s*\d+\|\s?", "", body, flags=re.M)
    rem = []
    for tok, (title, cwe, owasp, sev) in CAT.items():
        if tok in body:
            rem.append({
                "title": title, "cwe": cwe, "owasp": owasp, "severity": sev,
                "lines": [1, 1], "snippet": tok, "desc": "still present",
                "impact": "unchanged", "fix": "remove it",
            })
    return {"resolved": not rem, "remaining": rem, "regressions": ""}


def _emb(t):
    import hashlib
    d = hashlib.sha256(t.encode("utf-8", "replace")).digest()
    return [b / 255.0 for b in d[:16]]


def _reply(sys, user):
    if "remediation engineer" in sys:
        return _patch(user)
    if "reviewer verifying" in sys:
        return _verify(user)
    return _analyze(user)


class H(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_POST(self):
        n = int(self.headers.get("Content-Length", 0))
        req = json.loads(self.rfile.read(n) or b"{}")
        if self.path.endswith("/embeddings") or "input" in req:
            inp = req.get("input", [])
            if isinstance(inp, str):
                inp = [inp]
            out = json.dumps({"data": [{"embedding": _emb(t)} for t in inp]})
        else:
            sys = user = ""
            for m in req.get("messages", []):
                if m.get("role") == "system":
                    sys = m.get("content", "")
                elif m.get("role") == "user":
                    user = m.get("content", "")
            content = json.dumps(_reply(sys, user))
            out = json.dumps({"choices": [{"message": {"role": "assistant", "content": content}}]})
        b = out.encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)


def start():
    srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    return srv, f"http://127.0.0.1:{srv.server_address[1]}/v1"
