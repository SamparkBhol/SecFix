import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from secfix.config import Cfg
from tests import stub

try:
    import numpy
    from secfix import index
    HAVE_INDEX = numpy is not None
except ImportError:
    HAVE_INDEX = False

try:
    from secfix import mcp_server
    HAVE_MCP = True
except ImportError:
    HAVE_MCP = False


def cfg(url):
    return Cfg(base_url=url, key="", model="stub", temp=0, timeout=20, retries=2,
               workers=1, attempts=1, max_chars=12000, overlap=20, verify=True,
               cache="", context=True, embed_model="stub-embed")


@unittest.skipUnless(HAVE_INDEX, "numpy not installed")
class Symbols(unittest.TestCase):
    def test_python(self):
        src = "def foo(x):\n    return x\n\nclass Bar:\n    def m(self):\n        return 1\n"
        names = [n for n, _ in index.symbols("a.py", src, "python")]
        self.assertIn("foo", names)
        self.assertIn("Bar", names)

    def test_js(self):
        names = [n for n, _ in index.symbols("a.js", "export function login(u){return u}\n", "javascript")]
        self.assertIn("login", names)


@unittest.skipUnless(HAVE_INDEX, "numpy not installed")
class Vector(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.srv, cls.url = stub.start()

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()

    def test_embed(self):
        v = index.embed(cfg(self.url), ["hello", "world"])
        self.assertEqual(len(v), 2)
        self.assertEqual(len(v[0]), 16)

    def test_no_embed_model_disables(self):
        c = cfg(self.url)
        c.embed_model = ""
        self.assertIsNone(index.embed(c, ["x"]))

    def test_build_and_related_excludes_self(self):
        d = tempfile.mkdtemp()
        a = os.path.join(d, "a.py")
        b = os.path.join(d, "b.py")
        with open(a, "w") as f:
            f.write("def alpha():\n    return authenticate()\n")
        with open(b, "w") as f:
            f.write("def authenticate():\n    return True\n")
        ix = index.Index()
        self.assertTrue(ix.build(cfg(self.url), [a, b]))
        r = ix.related(cfg(self.url), "who calls authenticate", a)
        self.assertTrue(r.strip())
        self.assertIn("authenticate", r)
        self.assertNotIn("alpha", r)

    def test_end_to_end_with_context(self):
        from secfix.llm import LLM
        from secfix.agent import Agent
        d = tempfile.mkdtemp()
        a = os.path.join(d, "a.py")
        b = os.path.join(d, "b.py")
        with open(a, "w") as f:
            f.write("def run(s):\n    return eval(s)\n")
        with open(b, "w") as f:
            f.write("def helper():\n    return 1\n")
        c = cfg(self.url)
        ix = index.Index()
        ix.build(c, [a, b])
        r = Agent(LLM(c), c, ix).run(a)
        self.assertTrue(r.vulns)
        self.assertEqual(r.vulns[0]["cwe"], "CWE-95")


@unittest.skipUnless(HAVE_MCP, "mcp not installed")
class Mcp(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.srv, cls.url = stub.start()
        cls.keep = {k: os.environ.get(k) for k in ("LLM_BASE_URL", "LLM_API_KEY", "LLM_MODEL")}
        os.environ.update(LLM_BASE_URL=cls.url, LLM_API_KEY="t", LLM_MODEL="stub")

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()
        for k, v in cls.keep.items():
            os.environ[k] = v if v is not None else ""

    def test_scan_code_tool(self):
        d = mcp_server.scan_code("def f(s):\n    return eval(s)\n", "python")
        self.assertTrue(d["vulns"])
        self.assertEqual(d["vulns"][0]["cwe"], "CWE-95")
        self.assertTrue(d["fixed"])

    def test_scan_file_tool(self):
        t = tempfile.mkdtemp()
        p = os.path.join(t, "x.py")
        with open(p, "w") as f:
            f.write("def g(s):\n    return eval(s)\n")
        d = mcp_server.scan_file(p)
        self.assertTrue(d["vulns"])
        self.assertIn("diff", d)


if __name__ == "__main__":
    unittest.main()
