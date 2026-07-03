from dataclasses import dataclass, field

from . import scan, patch, prompts, cache

SEV = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


@dataclass
class FileResult:
    path: str
    lang: str
    src: str
    vulns: list
    patched: str = ""
    notes: str = ""
    syntax_ok: bool = True
    syntax_msg: str = ""
    verified: bool = False
    fixed: bool = False
    remaining: list = field(default_factory=list)
    regress: str = ""
    error: str = ""
    cached: bool = False


class Agent:
    def __init__(self, llm, cfg, index=None):
        self.llm = llm
        self.cfg = cfg
        self.index = index

    def analyze(self, src, lang, path=None):
        vs = []
        for off, ch in scan.chunk(src, self.cfg.max_chars, self.cfg.overlap):
            ctx = self.index.related(self.cfg, ch, path) if self.index is not None else ""
            r = self.llm.ask(prompts.ANALYZE_SYS, prompts.analyze_usr(lang, ch, ctx))
            for v in _clean(r):
                _shift(v, off)
                vs.append(v)
        return _dedupe(_rank(vs))

    def _patch(self, src, lang, vs):
        r = self.llm.ask(prompts.PATCH_SYS, prompts.patch_usr(lang, src, vs))
        if not isinstance(r, dict):
            return "", ""
        return str(r.get("patched", "") or ""), str(r.get("notes", "") or "")

    def _verify(self, patched, lang, vs):
        r = self.llm.ask(prompts.VERIFY_SYS, prompts.verify_usr(lang, patched, vs))
        if not isinstance(r, dict):
            return False, list(vs), ""
        rem = _clean(r, "remaining")
        return bool(r.get("resolved")) and not rem, _rank(rem), str(r.get("regressions", "") or "")

    def run(self, path):
        src = scan.read(path)
        lang = scan.lang_of(path)
        res = FileResult(path, lang, src, [])
        ck = cache.key(self.cfg, lang, src) if self.cfg.cache else None
        if ck:
            hit = cache.get(self.cfg.cache, ck)
            if hit is not None:
                res.cached = True
                return cache.load(res, hit)
        try:
            res.vulns = self.analyze(src, lang, path)
        except Exception as e:
            res.error = f"analysis: {e}"
            return res
        if not res.vulns:
            if ck:
                cache.put(self.cfg.cache, ck, cache.dump(res))
            return res

        base = src
        targets = res.vulns
        for _ in range(max(1, self.cfg.attempts)):
            try:
                patched, notes = self._patch(base, lang, targets)
            except Exception as e:
                res.error = f"patch: {e}"
                break
            if not patched or patched.strip() == base.strip():
                break
            ok, msg = patch.validate(lang, patched)
            res.patched, res.notes = patched, notes
            res.syntax_ok, res.syntax_msg = ok, msg
            if not self.cfg.verify:
                res.fixed = ok
                break
            try:
                resolved, remaining, regress = self._verify(patched, lang, res.vulns)
            except Exception as e:
                res.error = f"verify: {e}"
                break
            res.verified = True
            res.remaining = remaining
            res.regress = regress
            if resolved and ok:
                res.fixed = True
                break
            base = patched
            targets = remaining or res.vulns
        if ck and not res.error:
            cache.put(self.cfg.cache, ck, cache.dump(res))
        return res


def _clean(r, key="vulns"):
    if not isinstance(r, dict):
        return []
    xs = r.get(key, []) or []
    if not isinstance(xs, list):
        return []
    out = []
    for v in xs:
        if not isinstance(v, dict):
            continue
        sv = str(v.get("severity", "info")).strip().lower()
        v["severity"] = sv if sv in SEV else "info"
        out.append(v)
    return out


def _shift(v, off):
    ln = v.get("lines")
    if isinstance(ln, list):
        v["lines"] = [x + off if isinstance(x, int) else x for x in ln]
    elif isinstance(ln, int):
        v["lines"] = ln + off


def _rank(vs):
    return sorted(vs, key=lambda v: (SEV.get(str(v.get("severity", "")).lower(), 5), _first(v)))


def _dedupe(vs):
    seen = set()
    out = []
    for v in vs:
        k = (
            str(v.get("cwe", "")).lower().strip(),
            _first(v),
            str(v.get("title", ""))[:48].lower().strip(),
        )
        if k in seen:
            continue
        seen.add(k)
        out.append(v)
    return out


def _first(v):
    ln = v.get("lines")
    if isinstance(ln, list) and ln and isinstance(ln[0], int):
        return ln[0]
    if isinstance(ln, int):
        return ln
    return 1 << 30
