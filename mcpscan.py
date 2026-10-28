"""MCP Server Trust Scan — deterministic health/trust audit of any public MCP server.

Checks (each pass/warn/fail, weighted score 0-100):
  reach, SEP-1649 server card at both well-known paths + required fields,
  JSON-RPC handshake (initialize echoes a protocolVersion, tools/list non-empty
  with inputSchema), HEAD support on card path, auth posture, and hygiene
  probes (accidental exposure of /.git/config, /.env).
Scans public (globally routable) hosts only — reuses server.py's SSRF guard.
"""
import json, time, urllib.request, urllib.parse, socket, ipaddress
import html as htmlmod

UA = "utils.bigfloppy.net-mcpscan/1.0 (trust audit; contact via site)"
TIMEOUT = 6
MAX_CONCURRENT = 3
_SEM = None  # lazy, server imports us in threads

def _sem():
    global _SEM
    if _SEM is None:
        import threading
        _SEM = threading.BoundedSemaphore(MAX_CONCURRENT)
    return _SEM

def _public(url):
    try:
        h = urllib.parse.urlparse(url).hostname or ""
        for ai in socket.getaddrinfo(h, None):
            ip = ipaddress.ip_address(ai[4][0])
            if not ip.is_global:
                return False
    except Exception:
        return False
    return True

def _get(url, head=False):
    req = urllib.request.Request(url, method="HEAD" if head else "GET",
                                 headers={"User-Agent": UA, "Accept": "*/*"})
    t0 = time.time()
    with urllib.request.urlopen(req, timeout=TIMEOUT) as r:
        body = r.read(65536)
        return r.status, dict((k.lower(), v) for k, v in r.headers.items()), body, int((time.time() - t0) * 1000)

def _post_json(url, obj):
    data = json.dumps(obj).encode()
    req = urllib.request.Request(url, data=data, method="POST",
                                 headers={"User-Agent": UA, "Content-Type": "application/json",
                                          "Accept": "application/json, text/event-stream"})
    t0 = time.time()
    with urllib.request.urlopen(req, timeout=TIMEOUT) as r:
        body = r.read(262144)
        return r.status, body, int((time.time() - t0) * 1000)

def _parse_jsonrpc(body):
    txt = body.decode("utf-8", "replace")
    if txt.startswith("event:") or "\n\n" in txt and "data:" in txt:  # SSE variant
        for line in txt.splitlines():
            if line.startswith("data:"):
                txt = line[5:].strip(); break
    try:
        return json.loads(txt)
    except Exception:
        return None

def scan(url, deep=True):
    """Return a full report dict. deep adds hygiene probes."""
    with _sem():
        return _scan_locked(url, deep)

def _scan_locked(url, deep):
    t0 = time.time()
    url = (url or "").strip()
    if url and "://" not in url:
        url = "https://" + url
    checks = []
    def chk(cid, title, status, detail, weight=0):
        checks.append({"id": cid, "title": title, "status": status, "detail": str(detail)[:300]})
        return weight
    pen = 0
    try:
        o = urllib.parse.urlparse(url)
        if o.scheme not in ("http", "https") or not o.hostname:
            raise ValueError("not a http(s) URL")
    except Exception as e:
        return {"error": "bad url: %s" % e, "url": url}
    origin = "%s://%s" % (o.scheme, o.netloc)
    ep = url if url.endswith("/mcp") or "/mcp" in o.path else origin + "/mcp"
    if not _public(origin):
        return {"error": "refusing to scan: host is not publicly routable", "url": url}
    card = None
    # --- reach + card presence (SEP-1649) ---
    card_paths = ["/.well-known/mcp/server-card.json", "/.well-known/mcp.json"]
    card_ok = []
    for cp in card_paths:
        try:
            st, hd, body, _ms = _get(origin + cp)
            if st == 200 and body.strip().startswith(b"{"):
                card = json.loads(body.decode("utf-8", "replace")); card_ok.append(cp)
        except Exception:
            pass
    if card_ok:
        pen += chk("card", "SEP-1649 server card present", "pass", "found at " + ", ".join(card_ok))
    else:
        pen += chk("card", "SEP-1649 server card present", "warn",
                   "no JSON card at either well-known path (recommended for MCP registry discovery)", 8)
    # --- card fields ---
    if card:
        missing = [f for f in ("protocolVersion", "serverInfo", "capabilities") if not card.get(f)]
        si = card.get("serverInfo") or {}
        missing += [f for f in ("name", "version") if not si.get(f)]
        if missing:
            pen += chk("card_fields", "Card required fields", "fail", "missing: " + ", ".join(missing), 12)
        else:
            pen += chk("card_fields", "Card required fields", "pass",
                       "protocolVersion %s, %s v%s" % (card.get("protocolVersion"), si.get("name"), si.get("version")))
    # --- handshake: initialize + tools/list ---
    init = tools = None
    try:
        st, body, _ms = _post_json(ep, {"jsonrpc": "2.0", "id": 1, "method": "initialize",
                                        "params": {"protocolVersion": "2025-06-18", "capabilities": {},
                                                   "clientInfo": {"name": "mcpscan", "version": "1.0"}}})
        init = _parse_jsonrpc(body)
        if not init or "result" not in init:
            pen += chk("initialize", "JSON-RPC initialize", "fail", "no result (status %s)" % st, 20)
        else:
            pv = (init["result"] or {}).get("protocolVersion")
            si = (init["result"] or {}).get("serverInfo") or {}
            pen += chk("initialize", "JSON-RPC initialize", "pass",
                       "%s v%s, protocol %s" % (si.get("name", "?"), si.get("version", "?"), pv))
        st2, body2, _ms = _post_json(ep, {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}})
        tools = _parse_jsonrpc(body2)
        tl = ((tools or {}).get("result") or {}).get("tools") or []
        if tl:
            noschema = [t.get("name") for t in tl[:50] if not t.get("inputSchema")]
            pen += chk("tools_list", "tools/list (%d tools)" % len(tl),
                       "warn" if noschema else "pass",
                       "no inputSchema on: %s" % ", ".join(noschema) if noschema else "all tools declare inputSchema",
                       4 if noschema else 0)
        else:
            pen += chk("tools_list", "tools/list", "fail", "empty or error response", 10)
    except Exception as e:
        pen += chk("handshake", "JSON-RPC handshake at " + ep, "fail", "%s" % e, 25)
    # --- HEAD support on card path (proxy/crawler friendliness) ---
    try:
        st, hd, _b, _ms = _get(origin + card_paths[0], head=True)
        pen += chk("head", "HEAD on card path", "pass" if st == 200 else "warn", "status %s" % st, 3 if st != 200 else 0)
    except Exception as e:
        pen += chk("head", "HEAD on card path", "warn", "%s" % e, 3)
    # --- auth posture (info) ---
    pen += chk("auth", "Auth posture", "info",
               "unauthenticated handshake succeeded" if init else "handshake failed, auth posture unknown")
    # --- hygiene probes ---
    if deep:
        for path, what in (("/.git/config", "git repo metadata"), ("/.env", "env file")):
            try:
                st, hd, body, _ms = _get(origin + path)
                leaky = st == 200 and (b"[" in body or b"=" in body) and len(body) > 8
                pen += chk("hygiene", "No accidental " + what + " exposure", "fail" if leaky else "pass",
                           "/%s returns %s (%d bytes)" % (path.strip("/"), st, len(body)) + (" — looks like a real file!" if leaky else ""), 15 if leaky else 0)
            except Exception:
                pen += chk("hygiene", "No accidental " + what + " exposure", "pass", path + " not served")
    score = max(0, 100 - pen)
    grade = "A" if score >= 90 else "B" if score >= 75 else "C" if score >= 60 else "D"
    verdict = {"A": "healthy, well-published MCP server", "B": "working server, minor publication gaps",
               "C": "notable gaps — fix fails/warns before you rely on it",
               "D": "broken or hard to trust — do not rely on this server"}[grade]
    return {"url": ep, "score": score, "grade": grade, "verdict": verdict,
            "checks": checks, "scanned_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "duration_ms": int((time.time() - t0) * 1000), "deep": bool(deep)}

if __name__ == "__main__":
    import sys
    print(json.dumps(scan(sys.argv[1], deep=True), indent=1))

# ---------- registry resolution + public report pages ----------
import os, re as _re
REGISTRY = "https://registry.modelcontextprotocol.io/v0/servers"
SCAN_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "scans")

def resolve_registry(name):
    """Resolve 'net.bigfloppy.utils/utils' (or fuzzy) -> live remote URL via official registry."""
    q = urllib.parse.quote(name, safe="")
    raw = urllib.request.urlopen(urllib.request.Request(
        REGISTRY + "?search=" + q + "&limit=25", headers={"User-Agent": UA, "Accept": "application/json"}),
        timeout=8).read()
    best = None
    for item in json.loads(raw.decode()).get("servers", []):
        sv = item.get("server") or {}
        meta = ((item.get("_meta") or {}).get("io.modelcontextprotocol.registry/official") or {})
        if sv.get("name") == name and meta.get("status") != "active" and best is None:
            best = None  # keep looking for an active exact match
        if sv.get("name") == name and meta.get("status") == "active":
            for r in sv.get("remotes", []):
                u = r.get("url") or ""
                if r.get("type") == "streamable-http" or u.endswith("/mcp") or "/mcp" in u:
                    return u
            best = best or ((sv.get("remotes") or [{}])[0].get("url"))
    return best

def _slugify(url):
    o = urllib.parse.urlparse(url if "://" in url else "https://" + url)
    s = _re.sub(r"[^a-z0-9.-]+", "-", (o.hostname or "") + (o.path.replace("/mcp", "") if o.path and o.path != "/" else "")).strip("-").lower()
    return s or "unknown"

def save_report(report):
    os.makedirs(SCAN_DIR, exist_ok=True)
    slug = _slugify(report.get("url", "unknown"))
    report["slug"] = slug
    with open(os.path.join(SCAN_DIR, slug + ".json"), "w") as f:
        json.dump(report, f)
    return slug

def list_reports():
    out = []
    if os.path.isdir(SCAN_DIR):
        for fn in sorted(os.listdir(SCAN_DIR)):
            if fn.endswith(".json"):
                try:
                    r = json.load(open(os.path.join(SCAN_DIR, fn)))
                    out.append({k: r.get(k) for k in ("slug", "url", "score", "grade", "verdict", "scanned_at")})
                except Exception:
                    pass
    return out

def load_report(slug):
    fn = os.path.join(SCAN_DIR, _re.sub(r"[^a-z0-9.-]", "", slug) + ".json")
    if os.path.isfile(fn):
        return json.load(open(fn))
    return None

def page_html(report, index_mode=False):
    """Shareable public page. Failing hygiene details are withheld (responsible disclosure)."""
    if index_mode:
        rows = "".join(
            "<tr><td><a href='/scan/%s'>%s</a></td><td>%s</td><td><b>%s %s</b></td></tr>" %
            (r["slug"], htmlmod.escape(r.get("url", "")), r.get("scanned_at", ""), r.get("score", "?"), r.get("grade", ""))
            for r in report)
        return """<!doctype html><html><head><meta charset=utf-8><title>MCP Server Trust Reports</title>
<style>body{font-family:system-ui;max-width:860px;margin:2rem auto;padding:0 1rem}table{border-collapse:collapse;width:100%%}td,th{border:1px solid #ddd;padding:6px}</style></head>
<body><h1>MCP Server Trust Reports</h1><p>Free, published trust audits of MCP servers — deterministic checks (SEP-1649 card, handshake, tools, HEAD, auth posture, hygiene). Score 0-100, grade A-D.</p>
<p>Scan any server live: <code>GET /x402/mcpscan?url=…</code> ($2 via x402/USDC) or free score-only <code>/v1/mcpscan?url=…</code>. Full detail withheld on public pages for failing hygiene checks (owners get full reports).</p>
<table><tr><th>server</th><th>scanned</th><th>score</th></tr>%s</table>
<p><i>Reports generated by an autonomous agent (utils.bigfloppy.net). No unsolicited contact with owners.</i></p></body></html>""" % rows
    col = {"A": "#27ae60", "B": "#2ecc71", "C": "#e67e22", "D": "#c0392b"}.get(report.get("grade"), "#333")
    rows = ""
    for c in report.get("checks", []):
        icon = {"pass": "&#10003;", "warn": "&#9888;", "fail": "&#10007;", "info": "&#8505;"}.get(c["status"], "?")
        detail = htmlmod.escape(c["detail"])
        if c["id"] == "hygiene" and c["status"] == "fail":
            detail = "ISSUE FOUND — detail withheld on public page. Owners: request full report (free re-scan offer)."
        rows += "<tr><td>%s</td><td>%s</td><td>%s</td></tr>" % (icon, htmlmod.escape(c["title"]), detail)
    return """<!doctype html><html><head><meta charset=utf-8><title>Trust report: %s — %s/100 (%s)</title>
<meta name="description" content="MCP Server Trust Report: %s scored %s/100 (%s). Deterministic checks: SEP-1649 card, handshake, tools, auth posture, hygiene.">
<style>body{font-family:system-ui;max-width:860px;margin:2rem auto;padding:0 1rem}.sc{font-size:3rem;color:%s}table{border-collapse:collapse;width:100%%}td{border:1px solid #ddd;padding:6px;vertical-align:top}</style></head>
<body><h1>MCP Server Trust Report</h1><p><code>%s</code></p>
<p class="sc">%s/100 &mdash; grade %s</p><p>%s</p>
<table><tr><th></th><th>check</th><th>result</th></tr>%s</table>
<p>Scanned %s. Deterministic, rules-based audit by <a href="/">utils.bigfloppy.net</a> (autonomous agent).<br>
Live scan of any server: <code>GET /x402/mcpscan?url=...</code> ($2, x402 USDC) &middot; free score-only: <code>/v1/mcpscan?url=...</code><br>
Failing hygiene details are withheld publicly (responsible disclosure).</p></body></html>""" % (
        htmlmod.escape(report.get("url", "")), report.get("score", "?"), report.get("grade", ""),
        htmlmod.escape(report.get("url", "")), report.get("score", "?"), report.get("grade", ""),
        col, htmlmod.escape(report.get("url", "")), report.get("score", "?"), report.get("grade", ""),
        htmlmod.escape(report.get("verdict", "")), rows, report.get("scanned_at", ""))

# ---------- free-report seeding for popular servers ----------
import threading as _th
SEED_URLS = [
    "https://mcp.context7.com/mcp", "https://mcp.deepwiki.com/mcp", "https://mcp.exa.ai/mcp",
    "https://mcp.notion.com/mcp", "https://api.githubcopilot.com/mcp/", "https://mcp.stripe.com",
    "https://mcp.atlassian.com/mcp", "https://mcp.sentry.dev/mcp", "https://mcp.zapier.com/api/mcp/mcp",
    "https://mcp.linear.app/mcp", "https://mcp.snag.ac/mcp", "https://tandem.ac/mcp",
    "https://api.inference.sh/mcp", "https://apexai.academy/mcp", "https://mcp.datadubai.ae/mcp",
    "https://easyvoice.ae/api/mcp", "https://mcp.goji.agency/mcp", "https://justidea.agency/mcp",
    "https://mcp.projectory.ae/mcp", "https://propick.ae/mcp", "https://mcp.getle.ad/mcp",
    "https://app.inside.ad/api/mcp", "https://www.beachclubs.ae/mcp", "https://prices.brainy.ae/mcp",
    "https://genosys.ae/mcp", "https://plantguide.ae/mcp", "https://events.aero/mcp/events",
    "https://api.ugc.africa/mcp", "https://www.hood.ag/api/mcp", "https://mcp.grovisor.ae/",
]
_seeding = False
def seed_worker(min_keep=20):
    global _seeding
    seen = set()
    for u in SEED_URLS:
        if len(list_reports()) >= min_keep: break
        slug = _slugify(u)
        if slug in seen or load_report(slug): continue
        seen.add(slug)
        try:
            r = scan(u, deep=True)
            if "error" not in r and r.get("score") is not None:
                save_report(r)
        except Exception:
            pass
    _seeding = False
def maybe_seed(min_keep=20):
    global _seeding
    if _seeding or len(list_reports()) >= min_keep: return
    _seeding = True
    _th.Thread(target=seed_worker, args=(min_keep,), daemon=True).start()
