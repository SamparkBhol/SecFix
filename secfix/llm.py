import json
import time

import httpx


class LLMError(Exception):
    pass


class LLM:
    def __init__(self, cfg):
        self.cfg = cfg
        h = {"Content-Type": "application/json"}
        if cfg.key:
            h["Authorization"] = f"Bearer {cfg.key}"
        self.c = httpx.Client(base_url=cfg.base_url, headers=h, timeout=cfg.timeout)

    def close(self):
        self.c.close()

    def __enter__(self):
        return self

    def __exit__(self, *a):
        self.close()

    def ask(self, sys, usr, as_json=True):
        body = {
            "model": self.cfg.model,
            "temperature": self.cfg.temp,
            "messages": [
                {"role": "system", "content": sys},
                {"role": "user", "content": usr},
            ],
        }
        if as_json:
            body["response_format"] = {"type": "json_object"}
        data = self._post(body)
        try:
            txt = data["choices"][0]["message"]["content"]
        except (KeyError, IndexError, TypeError):
            raise LLMError(f"unexpected response shape: {str(data)[:200]}")
        if not isinstance(txt, str):
            raise LLMError("response contained no text content")
        return _loads(txt) if as_json else txt

    def _post(self, body):
        last = None
        for i in range(max(1, self.cfg.retries)):
            try:
                r = self.c.post("/chat/completions", json=body)
            except httpx.HTTPError as e:
                last = e
                time.sleep(min(2 ** i, 20))
                continue
            if r.status_code == 400 and "response_format" in body:
                body = {k: v for k, v in body.items() if k != "response_format"}
                try:
                    r = self.c.post("/chat/completions", json=body)
                except httpx.HTTPError as e:
                    last = e
                    time.sleep(min(2 ** i, 20))
                    continue
            if r.status_code in (408, 409, 429, 500, 502, 503, 504):
                last = LLMError(f"http {r.status_code}: {r.text[:200]}")
                time.sleep(min(2 ** i, 20))
                continue
            if r.status_code >= 400:
                raise LLMError(f"http {r.status_code}: {r.text[:300]}")
            return r.json()
        raise LLMError(f"request failed after retries: {last}")


def _loads(t):
    t = t.strip()
    if t.startswith("```"):
        t = t[3:]
        if t[:4].lower() == "json":
            t = t[4:]
        if t.rstrip().endswith("```"):
            t = t.rstrip()[:-3]
    try:
        return json.loads(t)
    except json.JSONDecodeError:
        a = t.find("{")
        if a >= 0:
            try:
                return json.JSONDecoder().raw_decode(t, a)[0]
            except json.JSONDecodeError:
                pass
    raise LLMError("model did not return valid JSON")
