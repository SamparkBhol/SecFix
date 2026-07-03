import os

EXTS = {
    ".py": "python",
    ".js": "javascript",
    ".jsx": "jsx",
    ".mjs": "javascript",
    ".ts": "typescript",
    ".tsx": "typescript",
    ".php": "php",
    ".java": "java",
    ".rb": "ruby",
    ".go": "go",
    ".c": "c",
    ".h": "c",
    ".cc": "cpp",
    ".cpp": "cpp",
    ".cs": "csharp",
    ".rs": "rust",
}

SKIP = {
    ".git", "node_modules", "venv", ".venv", "env", "__pycache__", "dist",
    "build", ".mypy_cache", ".pytest_cache", ".idea", ".tox", "vendor",
    "site-packages",
}

MAXBYTES = 2_000_000


def lang_of(p):
    return EXTS.get(os.path.splitext(p)[1].lower())


def discover(paths, exts=None):
    if exts:
        exts = {e.lower() for e in exts}
    out = set()
    for p in paths:
        if os.path.isfile(p):
            if _pick(p, exts):
                out.add(p)
        elif os.path.isdir(p):
            for root, dirs, files in os.walk(p):
                dirs[:] = [d for d in dirs if d not in SKIP and not d.startswith(".")]
                for f in files:
                    fp = os.path.join(root, f)
                    if _pick(fp, exts):
                        out.add(fp)
    return sorted(out)


def _pick(fp, exts):
    e = os.path.splitext(fp)[1].lower()
    if not lang_of(fp):
        return False
    if exts and e not in exts:
        return False
    try:
        if os.path.getsize(fp) > MAXBYTES:
            return False
    except OSError:
        return False
    return True


def read(p):
    with open(p, encoding="utf-8", errors="replace") as fh:
        return fh.read()


def chunk(src, mx, ov=20):
    if len(src) <= mx:
        return [(0, src)]
    lines = src.splitlines()
    n = len(lines)
    out = []
    i = 0
    while i < n:
        j = i
        size = 0
        while j < n and size < mx:
            size += len(lines[j]) + 1
            j += 1
        out.append((i, "\n".join(lines[i:j])))
        if j >= n:
            break
        ovc = min(ov, (j - i) // 2)
        i = max(j - ovc, i + 1)
    return out
