import json


def _num(src):
    out = []
    for i, ln in enumerate(src.splitlines(), 1):
        out.append(f"{i:>5}| {ln}")
    return "\n".join(out)


ANALYZE_SYS = (
    "You are a senior application security engineer doing a manual secure code "
    "review. You receive one source snippet whose lines are prefixed with their "
    "line number. Find only genuine, exploitable security vulnerabilities: "
    "injection, broken auth, secrets in code, insecure crypto, deserialization, "
    "SSRF, path traversal, XSS, unsafe eval/exec, missing authorization, and "
    "similar. Judge each on the code as written; do not invent issues that are "
    "not present, and do not flag pure style. Reason about the whole snippet "
    "before answering.\n\n"
    "Return ONLY JSON, no prose, matching:\n"
    '{"vulns":[{"title":str,"cwe":str,"owasp":str,'
    '"severity":"critical|high|medium|low|info","lines":[start,end],'
    '"snippet":str,"desc":str,"impact":str,"fix":str}]}\n'
    "lines are 1-based against the numbered snippet. cwe like \"CWE-89\", owasp "
    "like \"A03:2021-Injection\". desc explains the flaw, impact states the risk "
    "if exploited, fix gives concrete remediation. Empty list if nothing is "
    "wrong."
)

PATCH_SYS = (
    "You are a secure code remediation engineer. You are given a complete source "
    "file and a list of confirmed vulnerabilities in it. Rewrite the file so "
    "every listed vulnerability is fixed, using idiomatic, secure patterns "
    "(parameterized queries, safe APIs, proper validation, strong hashing, least "
    "privilege). Preserve all existing functionality, public function and class "
    "signatures, imports still needed, and behaviour for valid input. Change as "
    "little as necessary. Do not add comments or explanatory text inside the "
    "code. Return the entire corrected file, not a fragment.\n\n"
    "Return ONLY JSON matching:\n"
    '{"patched":str,"notes":str}\n'
    "patched is the full new file content. notes briefly states what changed and "
    "why behaviour is preserved."
)

VERIFY_SYS = (
    "You are an independent security reviewer verifying a proposed patch. You "
    "receive the patched file (line-numbered) and the vulnerabilities it was "
    "meant to fix. For each one decide whether it is actually resolved in this "
    "code. Also note any obvious functional regression the patch may have "
    "introduced. Be strict: only mark resolved when the code truly no longer has "
    "the flaw.\n\n"
    "Return ONLY JSON matching:\n"
    '{"resolved":bool,"remaining":[{"title":str,"cwe":str,"owasp":str,'
    '"severity":str,"lines":[start,end],"snippet":str,"desc":str,"impact":str,'
    '"fix":str}],"regressions":str}\n'
    "resolved is true only when remaining is empty. remaining lists the "
    "vulnerabilities still present."
)


def analyze_usr(lang, code, ctx=""):
    s = f"language: {lang}\n\nsource:\n{_num(code)}"
    if ctx:
        s += (
            "\n\nrelated code from elsewhere in the codebase, for context only "
            "(do not report vulnerabilities inside it):\n" + ctx
        )
    return s


def patch_usr(lang, src, vs):
    return (
        f"language: {lang}\n\nvulnerabilities:\n{json.dumps(vs, indent=2)}\n\n"
        f"file:\n{src}"
    )


def verify_usr(lang, patched, vs):
    return (
        f"language: {lang}\n\nvulnerabilities to check:\n"
        f"{json.dumps(vs, indent=2)}\n\npatched source:\n{_num(patched)}"
    )
