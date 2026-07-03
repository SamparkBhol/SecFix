import os
import json
import hashlib
import tempfile

FIELDS = ("vulns", "patched", "notes", "syntax_ok", "syntax_msg",
          "verified", "fixed", "remaining", "regress")


def key(cfg, lang, src):
    h = hashlib.sha256()
    parts = [str(lang), cfg.model, str(cfg.temp), str(cfg.max_chars), str(cfg.overlap),
             str(cfg.attempts), "1" if cfg.verify else "0", src]
    h.update("\x00".join(parts).encode("utf-8", "replace"))
    return h.hexdigest()


def get(d, k):
    p = os.path.join(d, k + ".json")
    try:
        with open(p, encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, ValueError):
        return None
    return data if isinstance(data, dict) else None


def put(d, k, data):
    try:
        os.makedirs(d, exist_ok=True)
        fd, tmp = tempfile.mkstemp(dir=d, suffix=".tmp")
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(data, fh)
        os.replace(tmp, os.path.join(d, k + ".json"))
    except OSError:
        pass


def dump(res):
    return {f: getattr(res, f) for f in FIELDS}


def load(res, data):
    for f in FIELDS:
        if f in data:
            setattr(res, f, data[f])
    return res
