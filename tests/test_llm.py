import json
import os
import sys
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from secfix.config import Cfg
from secfix.llm import LLM, LLMError


def cfg(url, retries=1):
    return Cfg(
        base_url=url, key="", model="m", temp=0, timeout=10, retries=retries,
        workers=1, attempts=1, max_chars=12000, overlap=20, verify=True,
    )


def _serve(handler):
    srv = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, f"http://127.0.0.1:{srv.server_address[1]}/v1"


def _send(h, code, obj):
    b = json.dumps(obj).encode()
    h.send_response(code)
    h.send_header("Content-Type", "application/json")
    h.send_header("Content-Length", str(len(b)))
    h.end_headers()
    h.wfile.write(b)


class NoJsonMode(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_POST(self):
        n = int(self.headers.get("Content-Length", 0))
        body = json.loads(self.rfile.read(n) or b"{}")
        if "response_format" in body:
            _send(self, 400, {"error": "response_format not supported"})
            return
        _send(self, 200, {"choices": [{"message": {"content": '{"vulns": []}'}}]})


class NullContent(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_POST(self):
        n = int(self.headers.get("Content-Length", 0))
        self.rfile.read(n)
        _send(self, 200, {"choices": [{"message": {"content": None}}]})


class Fallback(unittest.TestCase):
    def test_400_fallback_single_retry(self):
        srv, url = _serve(NoJsonMode)
        try:
            out = LLM(cfg(url, retries=1)).ask("sys", "usr")
            self.assertEqual(out, {"vulns": []})
        finally:
            srv.shutdown()
            srv.server_close()

    def test_null_content_clean_error(self):
        srv, url = _serve(NullContent)
        try:
            with self.assertRaises(LLMError):
                LLM(cfg(url, retries=2)).ask("sys", "usr")
        finally:
            srv.shutdown()
            srv.server_close()


if __name__ == "__main__":
    unittest.main()
