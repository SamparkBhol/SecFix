import ast
import os
import re

import httpx
import numpy as np

from . import scan


def symbols(path, src, lang):
    out = []
    if lang == "python":
        try:
            tree = ast.parse(src)
        except SyntaxError:
            return out
        lines = src.splitlines()
        for n in ast.walk(tree):
            if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                a = n.lineno - 1
                b = getattr(n, "end_lineno", n.lineno)
                out.append((n.name, "\n".join(lines[a:b])[:1500]))
        return out
    lines = src.splitlines()
    pat = re.compile(r"^[ \t]*(?:export\s+)?(?:public|private|protected|static|async\s+)*"
                     r"(?:function|func|def|class|fn|sub)\s+([A-Za-z_$][\w$]*)")
    for i, ln in enumerate(lines):
        m = pat.match(ln)
        if m:
            out.append((m.group(1), "\n".join(lines[i:i + 24])[:1500]))
    return out


def embed(cfg, texts):
    texts = [t for t in texts if t.strip()]
    if not texts or not cfg.embed_model:
        return None
    h = {"Content-Type": "application/json"}
    if cfg.key:
        h["Authorization"] = f"Bearer {cfg.key}"
    try:
        r = httpx.post(cfg.base_url + "/embeddings", headers=h, timeout=cfg.timeout,
                       json={"model": cfg.embed_model, "input": texts})
        if r.status_code >= 400:
            return None
        rows = r.json()["data"]
        return [row["embedding"] for row in rows]
    except (httpx.HTTPError, KeyError, ValueError, TypeError):
        return None


def _unit(m):
    m = np.asarray(m, dtype="float32")
    n = np.linalg.norm(m, axis=1, keepdims=True)
    n[n == 0] = 1.0
    return m / n


class Index:
    def __init__(self):
        self.vecs = None
        self.meta = []

    def build(self, cfg, files):
        texts = []
        meta = []
        for f in files:
            try:
                src = scan.read(f)
            except OSError:
                continue
            for name, snip in symbols(f, src, scan.lang_of(f)):
                texts.append(f"{name}\n{snip}")
                meta.append((f, name, snip))
        if not texts:
            return False
        vs = embed(cfg, texts)
        if not vs or len(vs) != len(texts):
            return False
        self.vecs = _unit(vs)
        self.meta = meta
        return True

    def related(self, cfg, chunk, exclude, k=4):
        if self.vecs is None:
            return ""
        qv = embed(cfg, [chunk[:1500]])
        if not qv:
            return ""
        q = _unit(qv)[0]
        sims = self.vecs @ q
        out = []
        seen = set()
        for i in np.argsort(-sims):
            f, name, snip = self.meta[int(i)]
            if f == exclude or name in seen:
                continue
            seen.add(name)
            out.append(f"# {os.path.basename(f)} :: {name}\n{snip}")
            if len(out) >= k:
                break
        return "\n\n".join(out)
