import argparse
import collections
import json
import os
import re
import secrets
import shutil
import tempfile
from concurrent.futures import ThreadPoolExecutor
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

from .config import load
from .llm import LLM
from .agent import Agent
from . import scan, patch, report

EXT = {"python": ".py", "javascript": ".js", "jsx": ".jsx", "typescript": ".ts",
       "php": ".php", "java": ".java", "ruby": ".rb", "go": ".go", "c": ".c",
       "cpp": ".cpp", "csharp": ".cs"}
ORDER = ["critical", "high", "medium", "low", "info"]
CTYPE = {"md": "text/markdown", "html": "text/html", "sarif": "application/json",
         "pdf": "application/pdf"}

JOBS = {}
_ORDER = collections.deque()


def _safe(name):
    b = os.path.basename(str(name or "snippet"))
    b = re.sub(r"[^A-Za-z0-9._-]", "_", b) or "snippet"
    return b


def run_src(code, lang):
    if not code.strip():
        return {"error": "Paste some source first."}
    r = run_many([{"name": "snippet", "code": code, "lang": lang}], {})[0]
    return {"lang": r.lang, "vulns": r.vulns, "patched": r.patched, "notes": r.notes,
            "fixed": r.fixed, "verified": r.verified, "syntax_ok": r.syntax_ok,
            "syntax_msg": r.syntax_msg, "diff": _diff(r), "error": r.error}


def run_many(items, opts):
    cfg = load()
    if "verify" in opts:
        cfg.verify = bool(opts["verify"])
    if opts.get("attempts"):
        try:
            cfg.attempts = max(1, int(opts["attempts"]))
        except (TypeError, ValueError):
            pass
    if opts.get("context"):
        cfg.context = True
    tmp = tempfile.mkdtemp(prefix="secfixui_")
    plan = []
    try:
        for it in items:
            code = str(it.get("code", ""))
            lang = str(it.get("lang", "") or "")
            disp = _safe(it.get("name", "snippet"))
            if not os.path.splitext(disp)[1]:
                disp += EXT.get(lang, ".py")
            p = os.path.join(tmp, disp)
            k = 1
            while os.path.exists(p):
                p = os.path.join(tmp, f"{k}_{disp}")
                k += 1
            with open(p, "w", encoding="utf-8") as f:
                f.write(code)
            plan.append((p, str(it.get("name") or disp)))
        idx = None
        if cfg.context:
            from . import index
            ix = index.Index()
            if ix.build(cfg, [p for p, _ in plan]):
                idx = ix
        llm = LLM(cfg)
        ag = Agent(llm, cfg, idx)
        out = {}
        with ThreadPoolExecutor(max_workers=max(1, cfg.workers)) as ex:
            fut = {ex.submit(ag.run, p): (p, d) for p, d in plan}
            for ft, (p, d) in fut.items():
                try:
                    r = ft.result()
                except Exception:
                    r = None
                if r is None:
                    continue
                r.path = d
                out[p] = r
        llm.close()
        return [out[p] for p, _ in plan if p in out]
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def _diff(r):
    return patch.diff(r.src, r.patched, r.path) if r.patched else ""


def _slim(r):
    return {"name": r.path, "lang": r.lang, "vulns": r.vulns, "patched": r.patched,
            "notes": r.notes, "fixed": r.fixed, "verified": r.verified,
            "syntax_ok": r.syntax_ok, "syntax_msg": r.syntax_msg, "diff": _diff(r),
            "src": r.src, "error": r.error}


def _summary(results):
    sev = {k: 0 for k in ORDER}
    tot = fixed = withf = 0
    for r in results:
        if r.vulns:
            withf += 1
        if r.fixed:
            fixed += 1
        for v in r.vulns:
            tot += 1
            s = str(v.get("severity", "info")).lower()
            sev[s if s in sev else "info"] += 1
    return {"files": len(results), "with": withf, "total": tot, "fixed": fixed, "sev": sev}


def _store(results):
    tok = secrets.token_hex(8)
    JOBS[tok] = results
    _ORDER.append(tok)
    while len(_ORDER) > 24:
        JOBS.pop(_ORDER.popleft(), None)
    return tok


class H(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _send(self, code, body, ctype, extra=None):
        b = body if isinstance(body, bytes) else body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(b)))
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(b)

    def do_GET(self):
        u = urlparse(self.path)
        if u.path in ("/", "/index.html"):
            self._send(200, PAGE, "text/html; charset=utf-8")
        elif u.path == "/health":
            self._send(200, '{"ok":true}', "application/json")
        elif u.path == "/report":
            self._report(parse_qs(u.query))
        elif u.path == "/patch":
            self._patch(parse_qs(u.query))
        else:
            self._send(404, "not found", "text/plain")

    def _report(self, q):
        results = JOBS.get(q.get("token", [""])[0])
        fmt = q.get("format", ["md"])[0]
        if results is None or fmt not in CTYPE:
            self._send(404, "unknown report", "text/plain")
            return
        d = tempfile.mkdtemp()
        try:
            report.emit(results, d, {fmt})
            p = os.path.join(d, "report." + fmt)
            with open(p, "rb") as f:
                data = f.read()
        except Exception as e:
            self._send(500, f"report failed: {e}", "text/plain")
            return
        finally:
            shutil.rmtree(d, ignore_errors=True)
        self._send(200, data, CTYPE[fmt],
                   {"Content-Disposition": f'attachment; filename="report.{fmt}"'})

    def _patch(self, q):
        results = JOBS.get(q.get("token", [""])[0])
        try:
            i = int(q.get("i", ["-1"])[0])
        except ValueError:
            i = -1
        if results is None or not (0 <= i < len(results)):
            self._send(404, "unknown patch", "text/plain")
            return
        r = results[i]
        body = r.patched or r.src
        fn = "fixed_" + _safe(r.path)
        self._send(200, body, "text/plain; charset=utf-8",
                   {"Content-Disposition": f'attachment; filename="{fn}"'})

    def do_POST(self):
        if self.path != "/scan":
            self._send(404, '{"error":"not found"}', "application/json")
            return
        n = int(self.headers.get("Content-Length", 0))
        try:
            req = json.loads(self.rfile.read(n) or b"{}")
        except ValueError:
            self._send(200, '{"error":"bad request"}', "application/json")
            return
        if "files" not in req:
            self._send(200, json.dumps(run_src(str(req.get("code", "")),
                       str(req.get("lang", "python")))), "application/json")
            return
        try:
            results = run_many(req.get("files", []), req.get("opts", {}))
        except Exception as e:
            self._send(200, json.dumps({"error": str(e)}), "application/json")
            return
        tok = _store(results)
        out = {"token": tok, "summary": _summary(results),
               "results": [_slim(r) for r in results]}
        self._send(200, json.dumps(out), "application/json")


def serve(host, port):
    return ThreadingHTTPServer((host, port), H)


def main(argv=None):
    ap = argparse.ArgumentParser(prog="secfix-web")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8000)
    a = ap.parse_args(argv)
    srv = serve(a.host, a.port)
    print(f"secfix ui on http://{a.host}:{a.port} (ctrl-c to stop)")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        srv.shutdown()


PAGE = r"""<!doctype html><html><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>secfix - Security Center</title>
<style>
*{box-sizing:border-box}
html,body{height:100%;margin:0}
body{font:11px Tahoma,"Segoe UI",Verdana,sans-serif;color:#000;
 background:linear-gradient(180deg,#4d90d8 0%,#7cb3e8 44%,#4f8f2a 52%,#79bd3f 100%);
 display:flex;align-items:flex-start;justify-content:center;padding:22px 12px 46px;overflow-x:hidden}
.win{width:min(1080px,100%);background:#ece9d8;border:1px solid #0831d9;border-radius:8px 8px 0 0;
 box-shadow:0 12px 34px rgba(0,0,0,.45);overflow:hidden;animation:pop .14s ease-out}
@keyframes pop{from{transform:scale(.97);opacity:.5}to{transform:scale(1);opacity:1}}
.tbar{height:29px;display:flex;align-items:center;gap:7px;padding:0 5px 0 6px;color:#fff;user-select:none;
 background:linear-gradient(180deg,#0997ff 0,#2b7bff 6%,#0a53e6 45%,#0a4bd6 90%,#0831d9 100%);
 text-shadow:1px 1px 1px rgba(0,0,0,.45);border-radius:7px 7px 0 0}
.tbar b{font-size:12px;flex:1}
.caps{display:flex;gap:3px}
.cap{width:22px;height:20px;border:1px solid #fff;border-radius:3px;color:#fff;display:grid;place-items:center;
 background:linear-gradient(180deg,#4aa0ff,#1157e0)}
.cap.x{background:linear-gradient(180deg,#f08a6c,#d24f30 45%,#b62d13)}
.menu{display:flex;gap:2px;padding:2px 6px;background:#ece9d8;border-bottom:1px solid #d6d2c2}
.menu span{padding:2px 8px;border-radius:3px}
.menu span:hover{background:#186bd6;color:#fff}
.tool{display:flex;align-items:center;gap:8px;flex-wrap:wrap;padding:6px 8px;
 background:linear-gradient(180deg,#faf9f5,#eceadd);border-bottom:1px solid #c9c4b4}
.btn{font:11px Tahoma;min-width:34px;padding:4px 10px;color:#000;cursor:default;border:1px solid #003c74;border-radius:3px;
 background:linear-gradient(180deg,#fefefe,#f2f0e7 46%,#e7e3d2 47%,#f8f7f2)}
.btn:hover{border-color:#e08a00;background:linear-gradient(180deg,#fff,#f7f3e6 46%,#efe8cf 47%,#fcfbf6)}
.btn:active{background:linear-gradient(180deg,#dedad0,#eef);box-shadow:inset 1px 1px 2px rgba(0,0,0,.28)}
.btn:disabled{color:#9a978a;border-color:#b3af9e;background:#ece9d8}
.btn.def{box-shadow:inset 0 0 0 1px #fff,0 0 0 2px rgba(122,170,255,.85);font-weight:bold}
.btn:focus-visible{outline:1px dotted #000;outline-offset:-4px}
.sep{width:1px;height:20px;background:#c9c4b4;margin:0 2px}
.opt{display:flex;align-items:center;gap:5px;color:#26324a}
.opt input[type=checkbox]{margin:0}
.opt input[type=number]{width:40px;font:11px Tahoma;border:1px solid #7f9db9;padding:2px}
select{font:11px Tahoma;border:1px solid #7f9db9;background:#fff;padding:2px 4px;border-radius:2px}
.grow{flex:1}
.body{display:grid;grid-template-columns:300px 1fr;gap:0;height:456px}
@media(max-width:760px){.body{grid-template-columns:1fr;height:auto}}
.left{border-right:1px solid #c9c4b4;display:flex;flex-direction:column;min-height:0}
.lvhead{display:grid;grid-template-columns:1fr 46px 66px;background:linear-gradient(180deg,#fff,#e8e5d7);
 border-bottom:1px solid #b9b4a3;color:#3a3a34}
.lvhead span{padding:4px 6px;border-right:1px solid #cfcaba;font-weight:bold}
.lv{flex:1;overflow:auto;background:#fff;min-height:120px}
.row{display:grid;grid-template-columns:1fr 46px 66px;cursor:default;border-bottom:1px solid #f1efe6}
.row>span{padding:4px 6px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;display:flex;align-items:center;gap:5px}
.row.on{background:#316ac5;color:#fff}
.row .st{gap:4px}
.dot{width:9px;height:9px;border-radius:50%;flex:0 0 9px;background:#b9b4a3}
.dot.err{background:#d13438}.dot.warn{background:#e8a200}.dot.info{background:#2166c9}.dot.ok{background:#17a81a}
.drop{margin:7px;padding:12px;border:1px dashed #9a9686;border-radius:3px;text-align:center;color:#66645c;background:#f7f6f0}
.drop.hot{border-color:#0a53e6;background:#eaf1ff;color:#0a3aa0}
.leftfoot{display:flex;gap:6px;padding:7px;border-top:1px solid #c9c4b4;background:#ece9d8}
.right{display:flex;flex-direction:column;min-height:0;background:#ece9d8}
.tabs{display:flex;gap:2px;padding:7px 8px 0;background:#ece9d8}
.tab{padding:4px 14px;border:1px solid #b9b4a3;border-bottom:0;border-radius:4px 4px 0 0;background:#ded9c9;color:#3a3a34}
.tab.on{background:#fff;position:relative;top:1px;font-weight:bold;color:#000}
.pane{flex:1;overflow:auto;margin:0 8px 8px;border:1px solid #b9b4a3;background:#fff;padding:8px;min-height:150px}
.src-meta{display:flex;gap:8px;align-items:center;margin-bottom:6px}
.src-meta input{flex:1;font:11px Tahoma;border:1px solid #7f9db9;padding:3px 5px}
textarea{width:100%;height:300px;resize:vertical;font:12px/1.45 "Lucida Console","Courier New",monospace;
 border:1px solid #7f9db9;background:#fff;padding:7px;color:#111}
.empty{color:#66645c;padding:18px 8px;text-align:center}
.msg{display:flex;gap:9px;padding:8px 4px;border-bottom:1px solid #eceae0;align-items:flex-start}
.msg:last-child{border-bottom:0}
.ic{flex:0 0 24px;width:24px;height:24px;display:grid;place-items:center;color:#fff;font-weight:bold;font-size:14px}
.ic.err,.ic.info{border-radius:50%}
.ic.err{background:radial-gradient(circle at 34% 30%,#ff7b7b,#cf0000);box-shadow:inset 0 0 0 1px #8f0000}
.ic.info{background:radial-gradient(circle at 34% 30%,#7bb8ff,#0a5bd3);box-shadow:inset 0 0 0 1px #063f96;font-family:Georgia,serif;font-style:italic}
.ic.warn{width:26px;height:24px;color:#000;background:linear-gradient(#ffd23a,#e8a200);clip-path:polygon(50% 3%,97% 94%,3% 94%)}
.mtop{display:flex;align-items:center;gap:8px;flex-wrap:wrap}
.sev{font:10px Tahoma;font-weight:bold;color:#fff;padding:1px 6px;border-radius:2px}
.sev.err{background:#c4302b}.sev.warn{background:#c98a00}.sev.info{background:#2166c9}
.meta{color:#5a5850;margin:2px 0 4px}
.fix{margin-top:3px}
pre.diff{margin:0;font:12px/1.4 "Lucida Console","Courier New",monospace;white-space:pre;overflow:auto}
.diff .add{color:#127a12;background:#eafbe7;display:block}
.diff .del{color:#c02626;background:#fdeaea;display:block}
.diff .hnk{color:#5b3fb0;display:block}
.patchbar{display:flex;gap:8px;align-items:center;margin-bottom:7px}
.tag{font:10px Tahoma;padding:2px 7px;border-radius:2px;background:#eee}
.tag.ok{background:#dff3df;color:#0f6f12}.tag.bad{background:#fbe3e3;color:#a11}
.sbar{display:flex;align-items:center;gap:8px;padding:3px 5px;background:#ece9d8;border-top:1px solid #fff}
.cell{border:1px solid;border-color:#919b9c #fff #fff #919b9c;padding:3px 8px;background:#ece9d8}
#stat{flex:1}
.counts{display:flex;gap:5px;align-items:center}
.pill{font:10px Tahoma;color:#fff;padding:1px 6px;border-radius:8px}
.pbar{width:130px;height:15px;border:1px solid #7f9db9;background:#fff;padding:1px;display:none}
.pbar.on{display:block}
.pbar>i{display:block;height:100%;background-size:22px 100%;
 background-image:repeating-linear-gradient(90deg,#2fbf2a 0 12px,transparent 12px 14px);animation:march .7s linear infinite}
@keyframes march{from{background-position:0 0}to{background-position:22px 0}}
.grip{width:14px;height:14px;background:repeating-linear-gradient(135deg,#fff 0 1px,transparent 1px 2px,#919b9c 2px 3px,transparent 3px 4px)}
.task{position:fixed;left:0;right:0;bottom:0;height:30px;display:flex;align-items:center;
 background:linear-gradient(180deg,#3168d5,#245edc 8%,#4b95f4 52%,#2b6bd8 92%,#1f5bd0);border-top:1px solid #1042c4}
.start{height:100%;padding:0 20px 0 11px;font:italic 700 15px Tahoma;color:#fff;display:flex;align-items:center;gap:7px;
 background:linear-gradient(180deg,#59b13a,#3f9e22 48%,#2c8014);border-radius:0 11px 11px 0/0 13px 13px 0;text-shadow:1px 1px 1px #14520a}
.start .o{width:16px;height:16px;border-radius:50%;background:radial-gradient(circle at 35% 30%,#fff,#bfe6a8)}
.clock{margin-left:auto;height:100%;display:flex;align-items:center;padding:0 13px;color:#fff;
 background:linear-gradient(180deg,#1e8fdc,#1aa0ea);border-left:1px solid #16408f}
@media(prefers-reduced-motion:reduce){.win{animation:none}.pbar>i{animation:none}}
</style></head><body>
<div class="win">
 <div class="tbar">
  <svg width="16" height="16" viewBox="0 0 16 16"><path d="M8 1 2 3v5c0 3 2.6 5.6 6 7 3.4-1.4 6-4 6-7V3z" fill="#2b7bff" stroke="#fff" stroke-width="1"/><path d="M5.4 8.2 7 9.8 10.8 5.6" fill="none" stroke="#fff" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round"/></svg>
  <b>secfix &mdash; Security Center</b>
  <div class="caps"><span class="cap">_</span><span class="cap">&#9633;</span><span class="cap x">&#215;</span></div>
 </div>
 <div class="menu"><span>File</span><span>Scan</span><span>Report</span><span>Help</span></div>
 <div class="tool">
  <button class="btn def" id="scan">&#9658; Scan all</button>
  <span class="sep"></span>
  <button class="btn" id="newf">+ New file</button>
  <button class="btn" id="sample">Load sample</button>
  <span class="sep"></span>
  <label class="opt"><input type="checkbox" id="verify" checked> Verify</label>
  <label class="opt">Attempts <input type="number" id="attempts" min="1" max="5" value="2"></label>
  <label class="opt"><input type="checkbox" id="context"> Cross-file</label>
  <label class="opt">Fail on
   <select id="failon"><option value="critical">Critical</option><option value="high" selected>High</option>
    <option value="medium">Medium</option><option value="low">Low</option></select></label>
  <span class="grow"></span>
  <span class="sep"></span>
  <button class="btn rep" data-f="md" disabled>Report .md</button>
  <button class="btn rep" data-f="html" disabled>.html</button>
  <button class="btn rep" data-f="pdf" disabled>.pdf</button>
  <button class="btn rep" data-f="sarif" disabled>.sarif</button>
 </div>
 <div class="body">
  <div class="left">
   <div class="lvhead"><span>File</span><span>Lang</span><span>Result</span></div>
   <div class="lv" id="lv"></div>
   <div class="drop" id="drop">Drop source files here, or use <b>+ New file</b>.<br><input type="file" id="file" multiple hidden><a href="#" id="browse">browse</a></div>
   <div class="leftfoot"><button class="btn" id="del">Remove</button><button class="btn" id="clear">Clear all</button></div>
  </div>
  <div class="right">
   <div class="tabs">
    <div class="tab on" data-t="src">Source</div>
    <div class="tab" data-t="find">Findings</div>
    <div class="tab" data-t="patch">Patch</div>
   </div>
   <div class="pane" id="pane"></div>
  </div>
 </div>
 <div class="sbar">
  <span class="cell" id="stat">Ready. Add a file to begin.</span>
  <span class="pbar" id="prog"><i></i></span>
  <span class="cell counts" id="counts">0 files</span>
  <span class="grip"></span>
 </div>
</div>
<div class="task"><span class="start"><span class="o"></span>start</span><span class="clock" id="clk"></span></div>
<script>
var $=function(s){return document.querySelector(s)};
var LX={".py":"python",".js":"javascript",".jsx":"jsx",".ts":"typescript",".php":"php",".java":"java",".rb":"ruby",".go":"go",".c":"c",".cpp":"cpp",".cs":"csharp"};
var SAMPLES={
 python:"import hashlib, os, sqlite3\n\ndef check(user, pw):\n    con = sqlite3.connect('app.db')\n    q = \"select id from users where name = '%s'\" % user\n    row = con.execute(q).fetchone()\n    if row and hashlib.md5(pw.encode()).hexdigest() == row[1]:\n        return row[0]\n\ndef reset(user):\n    os.system('rm -f /var/sess/' + user + '.sess')\n",
 javascript:"const { exec } = require('child_process');\nconst app = require('express')();\napp.get('/ping', (req, res) => {\n  exec('ping -c 1 ' + req.query.host, (e, out) => res.send(out));\n});\napp.post('/calc', (req, res) => {\n  res.json({ r: eval(req.body.expr) });\n});\n",
 php:"<?php\n$dir = '/var/www/uploads/';\nif (isset($_GET['view'])) {\n    echo file_get_contents($dir . $_GET['view']);\n}\nif (isset($_GET['convert'])) {\n    system('convert ' . $_GET['convert'] . ' out.png');\n}\n"};
var S={files:[],sel:-1,tab:"src",token:null,busy:false};
function esc(s){return String(s==null?'':s).replace(/[&<>\"]/g,function(c){return{'&':'&amp;','<':'&lt;','>':'&gt;','\"':'&quot;'}[c]})}
function extlang(name){var i=name.lastIndexOf('.');return i<0?'python':(LX[name.slice(i).toLowerCase()]||'python')}
function sevrank(v){var m={critical:0,high:1,medium:2,low:3,info:4};var b=5;(v||[]).forEach(function(x){var r=m[String(x.severity||'info').toLowerCase()];if(r<b)b=r});return b}
function dot(f){if(!f.res)return'';if(f.res.error)return'<span class="dot"></span>';if(f.res.fixed&&!(f.res.vulns||[]).length)return'<span class="dot ok"></span>';var r=sevrank(f.res.vulns);return'<span class="dot '+(r<=1?'err':r===2?'warn':r<=3?'info':'ok')+'"></span>'}
function statword(f){if(!f.res)return'—';if(f.res.error)return'error';if(!f.res.vulns.length)return'clean';return f.res.fixed?'fixed':(f.res.vulns.length+' open')}
function drawlist(){
 var h=S.files.map(function(f,i){
  return '<div class="row'+(i===S.sel?' on':'')+'" data-i="'+i+'"><span>'+esc(f.name)+'</span><span>'+esc(f.lang)+'</span><span class="st">'+dot(f)+statword(f)+'</span></div>'}).join('');
 $('#lv').innerHTML=h||'<div class="empty">No files yet.</div>';
 $('#counts').textContent=S.files.length+(S.files.length===1?' file':' files');
}
function sevJson(v){var s=String(v.severity||'info').toLowerCase();if(s==='critical'||s==='high')return['err','&#10006;'];if(s==='medium')return['warn','!'];return['info','i']}
function lines(l){if(Array.isArray(l)&&l.length){var a=l[0],b=l[l.length-1];return a===b?a:a+'&ndash;'+b}if(typeof l==='number')return l;return '?'}
function tags(v){var t=[];[v.cwe,v.owasp].forEach(function(x){if(!x)return;Array.isArray(x)?t=t.concat(x):t.push(x)});return t.length?' &middot; '+t.map(esc).join(' &middot; '):''}
function findRow(v){var s=sevJson(v),c=s[0];
 return '<div class="msg"><span class="ic '+c+'">'+s[1]+'</span><div><div class="mtop"><b>'+esc(v.title||'Finding')+'</b><span class="sev '+c+'">'+esc(String(v.severity||'info').toUpperCase())+'</span></div>'+
  '<div class="meta">line '+lines(v.lines)+tags(v)+'</div><div>'+esc(v.desc)+'</div>'+
  (v.impact?'<div class="meta"><b>Risk.</b> '+esc(v.impact)+'</div>':'')+
  (v.fix?'<div class="fix"><b>Fix.</b> '+esc(v.fix)+'</div>':'')+'</div></div>'}
function diffhtml(s){return s.split('\n').map(function(l){var e=esc(l);
 if(l.charAt(0)==='+')return'<span class="add">'+e+'</span>';if(l.charAt(0)==='-')return'<span class="del">'+e+'</span>';
 if(l.indexOf('@@')===0)return'<span class="hnk">'+e+'</span>';return e}).join('\n')}
function drawpane(){
 var f=S.files[S.sel],p=$('#pane');
 if(!f){p.innerHTML='<div class="empty">Select a file, or add one with <b>+ New file</b>.</div>';return}
 if(S.tab==='src'){
  p.innerHTML='<div class="src-meta"><input id="fname" value="'+esc(f.name)+'"><select id="flang"></select></div><textarea id="code" spellcheck="false"></textarea>';
  var sel=$('#flang');['python','javascript','jsx','typescript','php','java','ruby','go','c','cpp','csharp'].forEach(function(l){var o=document.createElement('option');o.value=l;o.textContent=l;if(l===f.lang)o.selected=true;sel.appendChild(o)});
  $('#code').value=f.code;
  $('#code').oninput=function(){f.code=this.value};
  $('#fname').oninput=function(){f.name=this.value;drawlist()};
  sel.onchange=function(){f.lang=this.value;drawlist()};
 }else if(S.tab==='find'){
  if(!f.res){p.innerHTML='<div class="empty">Not scanned yet. Click <b>Scan all</b>.</div>';return}
  if(f.res.error){p.innerHTML=findRow({severity:'high',title:'Scan failed',desc:f.res.error,fix:'Check that an LLM endpoint is set in .env (see .env.example).'});return}
  p.innerHTML=(f.res.vulns||[]).length?f.res.vulns.map(findRow).join(''):'<div class="empty">No vulnerabilities found in this file.</div>';
 }else{
  if(!f.res||!f.res.diff){p.innerHTML='<div class="empty">No patch. Scan a file with findings to see a fix.</div>';return}
  var vr=f.res.fixed?'<span class="tag ok">verified fixed</span>':'<span class="tag bad">not verified</span>';
  var sx=f.res.syntax_ok?'<span class="tag ok">parses</span>':'<span class="tag bad">syntax failed</span>';
  p.innerHTML='<div class="patchbar">'+vr+sx+'<button class="btn" id="dl">Download fixed file</button></div>'+
   (f.res.notes?'<div class="meta">'+esc(f.res.notes)+'</div>':'')+'<pre class="diff">'+diffhtml(f.res.diff)+'</pre>';
  $('#dl').onclick=function(){if(S.token)location.href='/patch?token='+S.token+'&i='+S.sel};
 }
}
function draw(){drawlist();drawpane();
 document.querySelectorAll('.tab').forEach(function(t){t.classList.toggle('on',t.dataset.t===S.tab)});
 document.querySelectorAll('.rep').forEach(function(b){b.disabled=!S.token})}
function select(i){S.sel=i;draw()}
function addfile(name,lang,code){S.files.push({name:name,lang:lang||extlang(name),code:code||'',res:null});S.sel=S.files.length-1;S.token=null;draw()}
function stat(t){$('#stat').textContent=t}
function busy(b){S.busy=b;$('#prog').classList.toggle('on',b);$('#scan').disabled=b}
function counts(sm){var m={critical:'#c4302b',high:'#d9534f',medium:'#c98a00',low:'#2166c9',info:'#6b6b6b'};
 var pills=['critical','high','medium','low'].filter(function(k){return sm.sev[k]}).map(function(k){return'<span class="pill" style="background:'+m[k]+'">'+sm.sev[k]+' '+k+'</span>'}).join(' ');
 $('#counts').innerHTML=sm.files+' files &middot; '+sm.total+' findings &middot; '+sm.fixed+' fixed '+pills}
async function scan(){
 if(!S.files.length){stat('Add a file first.');return}
 S.files.forEach(function(f){f.code=f.code||''});
 busy(true);stat('Scanning '+S.files.length+' file(s)…');
 var opts={verify:$('#verify').checked,attempts:+$('#attempts').value,context:$('#context').checked,failon:$('#failon').value};
 try{
  var r=await fetch('/scan',{method:'POST',headers:{'Content-Type':'application/json'},
   body:JSON.stringify({files:S.files.map(function(f){return{name:f.name,code:f.code,lang:f.lang}}),opts:opts})});
  var d=await r.json();
  if(d.error){stat('Scan failed — '+d.error);busy(false);return}
  S.token=d.token;
  d.results.forEach(function(rs,i){if(S.files[i])S.files[i].res=rs});
  counts(d.summary);
  stat(d.summary.total?('Done. '+d.summary.total+' finding(s), '+d.summary.fixed+' fixed & verified.'):'Done. No vulnerabilities found.');
  if(S.sel<0&&S.files.length)S.sel=0;
  S.tab='find';draw();
 }catch(e){stat('Scan failed — the server is not reachable.')}
 busy(false)}
$('#scan').onclick=scan;
$('#newf').onclick=function(){var n=S.files.length+1;addfile('file'+n+'.py','python','');S.tab='src';draw()};
$('#sample').onclick=function(){addfile('sample.py','python',SAMPLES.python);S.tab='src';draw()};
$('#del').onclick=function(){if(S.sel<0)return;S.files.splice(S.sel,1);S.sel=Math.min(S.sel,S.files.length-1);S.token=null;draw()};
$('#clear').onclick=function(){S.files=[];S.sel=-1;S.token=null;stat('Cleared.');draw()};
$('#lv').onclick=function(e){var r=e.target.closest('.row');if(r)select(+r.dataset.i)};
document.querySelectorAll('.tab').forEach(function(t){t.onclick=function(){S.tab=t.dataset.t;draw()}});
document.querySelectorAll('.rep').forEach(function(b){b.onclick=function(){if(S.token)location.href='/report?token='+S.token+'&format='+b.dataset.f}});
function readfiles(fl){Array.prototype.forEach.call(fl,function(file){var rd=new FileReader();rd.onload=function(){addfile(file.name,extlang(file.name),rd.result)};rd.readAsText(file)})}
$('#browse').onclick=function(e){e.preventDefault();$('#file').click()};
$('#file').onchange=function(){readfiles(this.files);this.value=''};
var dz=$('#drop');
dz.ondragover=function(e){e.preventDefault();dz.classList.add('hot')};
dz.ondragleave=function(){dz.classList.remove('hot')};
dz.ondrop=function(e){e.preventDefault();dz.classList.remove('hot');readfiles(e.dataTransfer.files)};
function clock(){var d=new Date(),h=d.getHours(),m=d.getMinutes(),ap=h<12?'AM':'PM';h=h%12||12;$('#clk').textContent=h+':'+(m<10?'0'+m:m)+' '+ap}
clock();setInterval(clock,10000);
draw();
</script></body></html>"""


if __name__ == "__main__":
    main()
