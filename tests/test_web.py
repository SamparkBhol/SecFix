import os
import sys
import unittest

import httpx

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from secfix import web
from tests import stub


class Web(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.sstub, url = stub.start()
        os.environ.update(LLM_BASE_URL=url, LLM_API_KEY="t", LLM_MODEL="stub")
        cls.srv = web.serve("127.0.0.1", 0)
        cls.port = cls.srv.server_address[1]
        import threading
        threading.Thread(target=cls.srv.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()
        cls.sstub.shutdown()

    def base(self):
        return f"http://127.0.0.1:{self.port}"

    def test_page(self):
        r = httpx.get(self.base() + "/", timeout=10)
        self.assertEqual(r.status_code, 200)
        self.assertIn("Security Center", r.text)
        self.assertIn("text/html", r.headers["content-type"])

    def test_scan(self):
        r = httpx.post(self.base() + "/scan", timeout=30,
                       json={"code": "def f(s):\n    return eval(s)\n", "lang": "python"})
        d = r.json()
        self.assertTrue(d["vulns"])
        self.assertEqual(d["vulns"][0]["cwe"], "CWE-95")
        self.assertTrue(d["fixed"])
        self.assertIn("eval", d["diff"])

    def test_empty(self):
        r = httpx.post(self.base() + "/scan", json={"code": "  ", "lang": "python"}, timeout=10)
        self.assertIn("error", r.json())

    def test_multi_scan_report_patch(self):
        files = [
            {"name": "a.py", "code": "def f(s):\n    return eval(s)\n", "lang": "python"},
            {"name": "b.py", "code": "def add(a, b):\n    return a + b\n", "lang": "python"},
        ]
        r = httpx.post(self.base() + "/scan", timeout=40,
                       json={"files": files, "opts": {"verify": True, "attempts": 2}})
        d = r.json()
        self.assertEqual(d["summary"]["files"], 2)
        self.assertEqual(len(d["results"]), 2)
        self.assertTrue(d["results"][0]["vulns"])
        self.assertEqual(d["results"][1]["vulns"], [])
        tok = d["token"]
        rep = httpx.get(self.base() + f"/report?token={tok}&format=md", timeout=15)
        self.assertEqual(rep.status_code, 200)
        self.assertIn("Secure Coding Assessment", rep.text)
        self.assertIn("attachment", rep.headers.get("content-disposition", ""))
        sar = httpx.get(self.base() + f"/report?token={tok}&format=sarif", timeout=15)
        self.assertEqual(sar.json()["version"], "2.1.0")
        pat = httpx.get(self.base() + f"/patch?token={tok}&i=0", timeout=15)
        self.assertEqual(pat.status_code, 200)
        self.assertNotIn("eval(", pat.text)

    def test_report_bad_token(self):
        r = httpx.get(self.base() + "/report?token=nope&format=md", timeout=10)
        self.assertEqual(r.status_code, 404)


if __name__ == "__main__":
    unittest.main()
