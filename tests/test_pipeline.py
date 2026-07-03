import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from secfix.config import Cfg
from secfix.llm import LLM, _loads, LLMError
from secfix.agent import Agent, FileResult, _dedupe, _clean
from secfix import scan, patch, report, cli
from tests import stub


def cfg(url):
    return Cfg(
        base_url=url, key="test", model="stub", temp=0, timeout=30, retries=3,
        workers=2, attempts=2, max_chars=12000, overlap=20, verify=True,
    )


class Loads(unittest.TestCase):
    def test_plain(self):
        self.assertEqual(_loads('{"a":1}'), {"a": 1})

    def test_fenced(self):
        self.assertEqual(_loads('```json\n{"a":1}\n```'), {"a": 1})

    def test_noise(self):
        self.assertEqual(_loads('sure:\n{"a":1}\nthanks'), {"a": 1})

    def test_trailing_brace_prose(self):
        self.assertEqual(_loads('{"vulns":[]}\n\nHope this helps :}'), {"vulns": []})

    def test_bad(self):
        with self.assertRaises(LLMError):
            _loads("nothing here")


class Scan(unittest.TestCase):
    def test_lang(self):
        self.assertEqual(scan.lang_of("a/b.py"), "python")
        self.assertIsNone(scan.lang_of("a/b.txt"))

    def test_chunk_small(self):
        self.assertEqual(scan.chunk("abc", 100), [(0, "abc")])

    def test_chunk_split(self):
        src = "\n".join(f"line{i}" for i in range(200))
        cs = scan.chunk(src, 300, 5)
        self.assertGreater(len(cs), 1)
        self.assertEqual(cs[0][0], 0)
        self.assertGreater(cs[1][0], 0)


class Dedupe(unittest.TestCase):
    def test(self):
        a = {"cwe": "CWE-89", "lines": [3, 3], "title": "SQLi"}
        b = {"cwe": "CWE-89", "lines": [3, 3], "title": "SQLi"}
        c = {"cwe": "CWE-79", "lines": [9, 9], "title": "XSS"}
        self.assertEqual(len(_dedupe([a, b, c])), 2)


class Validate(unittest.TestCase):
    def test_ok(self):
        ok, _ = patch.validate("python", "x = 1\n")
        self.assertTrue(ok)

    def test_bad(self):
        ok, _ = patch.validate("python", "def (:\n")
        self.assertFalse(ok)

    def test_backup_preserves_original(self):
        d = tempfile.mkdtemp()
        p = os.path.join(d, "f.py")
        with open(p, "w") as f:
            f.write("original\n")
        patch.write_out(p, "patch1\n")
        patch.write_out(p, "patch2\n")
        with open(p + ".bak") as f:
            self.assertEqual(f.read(), "original\n")
        with open(p) as f:
            self.assertEqual(f.read(), "patch2\n")

    def test_typescript_not_failed(self):
        ok, _ = patch.validate("typescript", "function f(x: number): number { return x }\n")
        self.assertTrue(ok)

    def test_jsx_not_failed(self):
        self.assertEqual(scan.lang_of("a/App.jsx"), "jsx")
        ok, _ = patch.validate("jsx", "function B(){return <div><img src='a'/><span>{x}</span></div>} module.exports=B\n")
        self.assertTrue(ok)


class Summarize(unittest.TestCase):
    def test_unknown_severity(self):
        class R:
            vulns = [{"severity": "weird"}, {"severity": "high"}]
            fixed = False
        s = report.summarize([R()])
        self.assertEqual(s["total"], 2)
        self.assertEqual(sum(s["sev"].values()), 2)
        self.assertEqual(s["sev"]["info"], 1)


class Report(unittest.TestCase):
    def _res(self):
        v = {"severity": "high", "title": "SQLi", "cwe": ["CWE-89", "CWE-564"],
             "owasp": 943, "lines": [1, 2], "desc": "d", "impact": "i", "fix": "f"}
        return FileResult("x.py", "python", "print(1)\n", [v])

    def test_list_and_nonstr_tags_no_crash(self):
        r = self._res()
        m = report.md([r], "ts")
        self.assertIn("CWE-89", m)
        self.assertIn("CWE-564", m)
        h = report.html_doc([r], "ts")
        self.assertIn("CWE-564", h)
        d = tempfile.mkdtemp()
        report.pdf([r], "ts", os.path.join(d, "r.pdf"))
        self.assertTrue(os.path.getsize(os.path.join(d, "r.pdf")) > 0)

    def test_status_no_verify_not_labeled_verified(self):
        r = FileResult("x.py", "python", "a\n", [{"severity": "high"}])
        r.patched, r.fixed, r.verified = "b\n", True, False
        m = report.md([r], "ts")
        self.assertIn("status: fixed", m)
        self.assertNotIn("fixed & verified", m)
        h = report.html_doc([r], "ts")
        self.assertNotIn("fixed &amp; verified", h)
        r.verified = True
        self.assertIn("fixed & verified", report.md([r], "ts"))

    def test_html_escapes_injection(self):
        v = {"severity": "high", "title": "<script>x</script>", "lines": [1],
             "desc": "d", "impact": "i", "fix": "f"}
        h = report.html_doc([FileResult("x.py", "python", "a\n", [v])], "ts")
        self.assertNotIn("<script>x</script>", h)
        self.assertIn("&lt;script&gt;", h)


class Clean(unittest.TestCase):
    def test_filters_non_dicts(self):
        self.assertEqual(_clean({"vulns": [{"a": 1}, "x", 5, None]}), [{"a": 1, "severity": "info"}])
        self.assertEqual(_clean(["not a dict"]), [])
        self.assertEqual(_clean({"remaining": [{"b": 2}]}, "remaining"), [{"b": 2, "severity": "info"}])

    def test_normalizes_severity(self):
        out = _clean({"vulns": [{"severity": "HIGH "}, {"severity": "weird"}, {"severity": "low"}]})
        self.assertEqual([v["severity"] for v in out], ["high", "info", "low"])


class Sarif(unittest.TestCase):
    def test_structure_and_levels(self):
        vs = [
            {"severity": "critical", "title": "RCE", "cwe": "CWE-94", "lines": [3, 5], "desc": "x"},
            {"severity": "low", "title": "Info leak", "cwe": ["CWE-200"], "lines": 9, "desc": "y"},
        ]
        r = FileResult("app/x.py", "python", "a\n", vs)
        d = tempfile.mkdtemp()
        out = report.emit([r], d, {"sarif"})
        self.assertTrue(any(x.endswith("report.sarif") for x in out))
        with open(os.path.join(d, "report.sarif")) as fh:
            doc = json.load(fh)
        self.assertEqual(doc["version"], "2.1.0")
        run = doc["runs"][0]
        self.assertEqual(run["tool"]["driver"]["name"], "secfix")
        res = run["results"]
        self.assertEqual(len(res), 2)
        self.assertEqual(res[0]["level"], "error")
        self.assertEqual(res[1]["level"], "note")
        self.assertEqual(res[0]["locations"][0]["physicalLocation"]["region"]["startLine"], 3)
        self.assertEqual(res[1]["locations"][0]["physicalLocation"]["region"]["startLine"], 9)
        self.assertEqual(res[0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"], "app/x.py")


class CacheMod(unittest.TestCase):
    def test_key_and_roundtrip(self):
        from secfix import cache
        from secfix.config import Cfg
        base = dict(base_url="u", key="", model="m", temp=0, timeout=10, retries=1,
                    workers=1, attempts=2, max_chars=100, overlap=5, verify=True)
        a = Cfg(**base)
        b = Cfg(**{**base, "model": "other"})
        self.assertEqual(cache.key(a, "python", "src"), cache.key(a, "python", "src"))
        self.assertNotEqual(cache.key(a, "python", "src"), cache.key(b, "python", "src"))
        self.assertNotEqual(cache.key(a, "python", "src"), cache.key(a, "python", "src2"))
        self.assertNotEqual(cache.key(a, "javascript", "src"), cache.key(a, "jsx", "src"))
        d = tempfile.mkdtemp()
        r = FileResult("p.py", "python", "s", [{"severity": "high"}])
        r.fixed = True
        cache.put(d, "k", cache.dump(r))
        r2 = cache.load(FileResult("p.py", "python", "s", []), cache.get(d, "k"))
        self.assertTrue(r2.fixed)
        self.assertEqual(r2.vulns, [{"severity": "high"}])

    def test_corrupt_entry_is_miss(self):
        from secfix import cache
        d = tempfile.mkdtemp()
        for bad in ("[]", '""', "0", "not json"):
            with open(os.path.join(d, "k.json"), "w") as fh:
                fh.write(bad)
            self.assertIsNone(cache.get(d, "k"))


class Apply(unittest.TestCase):
    def test_only_verified_written(self):
        d = tempfile.mkdtemp()
        a = os.path.join(d, "a.py")
        b = os.path.join(d, "b.py")
        with open(a, "w") as f:
            f.write("orig-a\n")
        with open(b, "w") as f:
            f.write("orig-b\n")
        ra = FileResult(a, "python", "orig-a\n", [{"severity": "high"}])
        ra.patched, ra.fixed, ra.syntax_ok = "fixed-a\n", True, True
        rb = FileResult(b, "python", "orig-b\n", [{"severity": "high"}])
        rb.patched, rb.fixed, rb.syntax_ok = "broken-b\n", False, True
        cli._apply([ra, rb], yes=True)
        with open(a) as f:
            self.assertEqual(f.read(), "fixed-a\n")
        with open(b) as f:
            self.assertEqual(f.read(), "orig-b\n")


class Chunk(unittest.TestCase):
    def test_long_lines_bounded(self):
        src = "\n".join("x" * 100 for _ in range(300))
        cs = scan.chunk(src, 2000, 20)
        self.assertLess(len(cs), 60)
        self.assertTrue(all(b for _, b in cs))


class ConfigBlank(unittest.TestCase):
    def test_blank_env_uses_default(self):
        from secfix import config
        keep = {k: os.environ.get(k) for k in ("LLM_TIMEOUT", "SECFIX_WORKERS", "LLM_TEMP")}
        try:
            os.environ["LLM_TIMEOUT"] = ""
            os.environ["SECFIX_WORKERS"] = "  "
            os.environ["LLM_TEMP"] = "bad"
            c = config.load()
            self.assertEqual(c.timeout, 120)
            self.assertGreaterEqual(c.workers, 1)
            self.assertEqual(c.temp, 0.0)
        finally:
            for k, v in keep.items():
                if v is None:
                    os.environ.pop(k, None)
                else:
                    os.environ[k] = v


class Pipeline(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.srv, cls.url = stub.start()

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()

    def test_end_to_end(self):
        c = cfg(self.url)
        ag = Agent(LLM(c), c)
        d = tempfile.mkdtemp()
        fp = os.path.join(d, "calc.py")
        with open(fp, "w") as f:
            f.write("def calc(s):\n    return eval(s)\n")
        r = ag.run(fp)
        self.assertTrue(r.vulns)
        self.assertEqual(r.vulns[0]["cwe"], "CWE-95")
        self.assertTrue(r.patched)
        self.assertNotIn("eval(", r.patched)
        self.assertTrue(r.syntax_ok)
        self.assertTrue(r.fixed)
        out = report.emit([r], os.path.join(d, "rep"), {"md", "html", "pdf"})
        self.assertTrue(any(x.endswith("report.md") for x in out))
        self.assertTrue(any(x.endswith("report.pdf") for x in out))

    def test_clean(self):
        c = cfg(self.url)
        ag = Agent(LLM(c), c)
        d = tempfile.mkdtemp()
        fp = os.path.join(d, "safe.py")
        with open(fp, "w") as f:
            f.write("def add(a, b):\n    return a + b\n")
        r = ag.run(fp)
        self.assertEqual(r.vulns, [])
        self.assertFalse(r.fixed)

    def test_multichunk_line_numbers(self):
        c = cfg(self.url)
        c.max_chars = 200
        ag = Agent(LLM(c), c)
        d = tempfile.mkdtemp()
        fp = os.path.join(d, "big.py")
        lines = [f"a{i} = {i}00000000" for i in range(60)]
        lines[54] = "result = eval(payload)"
        with open(fp, "w") as f:
            f.write("\n".join(lines) + "\n")
        r = ag.run(fp)
        hits = [v for v in r.vulns if v.get("cwe") == "CWE-95"]
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0]["lines"][0], 55)

    def test_cache_hit_skips_llm(self):
        d = tempfile.mkdtemp()
        cdir = os.path.join(d, "cache")
        fp = os.path.join(d, "calc.py")
        with open(fp, "w") as f:
            f.write("def calc(s):\n    return eval(s)\n")
        c1 = cfg(self.url)
        c1.cache = cdir
        r1 = Agent(LLM(c1), c1).run(fp)
        self.assertTrue(r1.fixed)
        self.assertFalse(r1.cached)
        c2 = cfg("http://127.0.0.1:9/v1")
        c2.cache = cdir
        r2 = Agent(LLM(c2), c2).run(fp)
        self.assertTrue(r2.cached)
        self.assertTrue(r2.fixed)
        self.assertEqual(r2.vulns[0]["cwe"], "CWE-95")

    def test_fail_on_threshold(self):
        d = tempfile.mkdtemp()
        with open(os.path.join(d, "x.py"), "w") as f:
            f.write("def add(a, b):\n    return a + b\n")
        env = {"LLM_BASE_URL": self.url, "LLM_API_KEY": "t", "LLM_MODEL": "stub"}
        old = {k: os.environ.get(k) for k in env}
        os.environ.update(env)
        try:
            self.assertEqual(cli.main([d, "-o", os.path.join(d, "r"), "-f", "md"]), 0)
        finally:
            for k, v in old.items():
                os.environ[k] = v if v is not None else ""


if __name__ == "__main__":
    unittest.main()
