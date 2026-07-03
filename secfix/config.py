import os
from dataclasses import dataclass


@dataclass
class Cfg:
    base_url: str
    key: str
    model: str
    temp: float
    timeout: int
    retries: int
    workers: int
    attempts: int
    max_chars: int
    overlap: int
    verify: bool
    cache: str = ""
    context: bool = False
    embed_model: str = ""


def _dotenv(p=".env"):
    if not os.path.exists(p):
        return
    with open(p, encoding="utf-8") as fh:
        for ln in fh:
            ln = ln.strip()
            if not ln or ln.startswith("#") or "=" not in ln:
                continue
            k, v = ln.split("=", 1)
            os.environ.setdefault(k.strip(), v.strip().strip('"').strip("'"))


def load():
    _dotenv()
    cpu = os.cpu_count() or 4

    def s(k, d):
        v = os.environ.get(k, "")
        v = v.strip() if v else ""
        return v or d

    def n(k, d, cast):
        try:
            return cast(s(k, d))
        except ValueError:
            return cast(d)

    return Cfg(
        base_url=s("LLM_BASE_URL", "https://api.openai.com/v1").rstrip("/"),
        key=os.environ.get("LLM_API_KEY", ""),
        model=s("LLM_MODEL", "gpt-4o-mini"),
        temp=n("LLM_TEMP", "0", float),
        timeout=n("LLM_TIMEOUT", "120", int),
        retries=n("LLM_RETRIES", "5", int),
        workers=n("SECFIX_WORKERS", str(min(8, cpu)), int),
        attempts=n("SECFIX_ATTEMPTS", "2", int),
        max_chars=n("SECFIX_MAX_CHARS", "12000", int),
        overlap=n("SECFIX_OVERLAP", "20", int),
        verify=s("SECFIX_VERIFY", "1") != "0",
        cache=os.environ.get("SECFIX_CACHE", "").strip(),
        context=s("SECFIX_CONTEXT", "0") not in ("0", "false", "no"),
        embed_model=os.environ.get("SECFIX_EMBED_MODEL", "").strip(),
    )
