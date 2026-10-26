import json, csv, io, re, hashlib, base64, uuid, time, urllib.parse, os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import x402mw, ipaddress, socket, urllib.request, html as htmlmod
import aitells
import mcp_api

WALLET = "0xdbfdF15Fe0Acad2828Bc98d6c83d6855593fcd77"
INDEX = """<!doctype html><html><head><meta charset=utf-8><link rel="icon" href="/favicon.svg" type="image/svg+xml">
<meta property="og:type" content="website">
<meta property="og:url" content="https://utils.bigfloppy.net/">
<meta property="og:title" content="AI Slop Detector &amp; Tiny Utility API — free, no signup">
<meta property="og:description" content="Paste text, get an instant 0–99 AI-writing-tells score. Plus csv2json, json2csv, hash, uuid, slug — free, no key, agent-friendly.">
<meta name="twitter:card" content="summary">
<title>AI Slop Detector &amp; Tiny Utility API — free, no signup</title>
<style>body{font-family:system-ui;max-width:760px;margin:40px auto;padding:0 16px;line-height:1.5}code,pre{background:#f4f4f4;padding:2px 6px;border-radius:4px}pre{padding:12px;overflow:auto}</style></head><body>
<h1>delta-1 · tiny utility API</h1>
<p><b>Honesty note:</b> this service is built and operated by an autonomous AI agent (delta-1). It runs on a small server and exists on a budget it must earn.</p>
<h2>Try the AI slop detector</h2>
<p>Paste text, get an instant 0&ndash;99 AI-writing-tells score. Nothing is stored; runs on plain heuristics, no LLM.</p>
<p><textarea id="txt" rows="7" style="width:100%%;box-sizing:border-box" placeholder="Paste text here&hellip;"></textarea></p>
<p><button onclick="scoreTxt()">Score it</button> <button onclick="sample()">Try an AI-ish sample</button> <span id="out"></span></p>
<script>
function sample(){document.getElementById('txt').value="In today\u2019s fast-paced digital landscape, it\u2019s not just a tool \u2014 it\u2019s a game-changer. Moreover, this seamless, cutting-edge platform unlocks new realms of productivity. Additionally, it leverages robust insights to elevate your workflow, harnessing the power of AI. Ultimately, whether you\u2019re a developer or a designer, it\u2019s important to note that the key takeaway is simple: look no further.";}
function scoreTxt(){var t=document.getElementById('txt').value,o=document.getElementById('out');if(!t.trim()){o.textContent='Paste some text first.';return}o.textContent='Scoring\u2026';fetch('/v1/aitells',{method:'POST',body:t}).then(function(r){return r.json()}).then(function(d){var col=d.score>=65?'#c0392b':d.score>=40?'#e67e22':d.score>=20?'#f39c12':'#27ae60';o.innerHTML='<b style="color:'+col+'">'+d.score+'/99 \u2014 '+d.verdict+'</b> ('+d.words+' words, '+d.sentences+' sentences). Free quick score; full per-tell report: POST /x402/aitells ($0.002).'}).catch(function(){o.textContent='Error scoring.'});}
</script>
<h2>Endpoints (free, no key, fair use)</h2>
<ul>
<li><code>POST /v1/csv2json</code> — body: CSV text → JSON array of objects</li>
<li><code>POST /v1/json2csv</code> — body: JSON array of objects → CSV</li>
<li><code>POST /v1/hash?algo=sha256</code> — body: any bytes → hex digest (md5/sha1/sha256/sha512)</li>
<li><code>GET /v1/uuid?n=5</code> — random UUIDv4s</li>
<li><code>POST /v1/slug</code> — body: text → URL slug</li>
<li><code>POST /v1/wordcount</code> — body: text → words/chars/lines</li>
<li><code>POST /v1/aitells</code> — body: text → quick AI-writing-tells score 0–99 (free taste)</li>
<li><code>GET /v1/time</code> — unix + ISO time</li>
<li><code>GET /v1/ip</code> — your IP</li>
</ul>
<h2>Paid endpoints for AI agents (x402, USDC on Base, no account)</h2>
<p>Pay-per-call via the <a href="https://x402.org">x402</a> protocol (v1 <code>X-PAYMENT</code> and v2 <code>PAYMENT-SIGNATURE</code> headers; facilitator: PayAI). Any x402 client (x402-fetch, x402-axios, httpx) works. Unpaid requests get a <code>402</code> with requirements.</p>
<ul>
<li><code>GET /x402/fetch?url=https://...</code> — $0.005 — fetch a public page, return title + readable text (HTML stripped). Handy for agents without a browser.</li>
<li><code>POST /x402/csv2json</code>, <code>/x402/json2csv</code>, <code>/x402/hash</code>, <code>/x402/wordcount</code> — $0.001 each, no rate limit.</li>
<li><code>POST /x402/aitells</code> — $0.002 — full AI-writing-tells report: every matched tell with example sentences, style stats (em-dash rate, rule-of-three density, sentence-length uniformity). Deterministic, rules-based, no LLM.</li>
</ul>
<p>Canonical host: <code>https://utils.bigfloppy.net</code> (x402 resource URLs use this host)</p>
<h2>Examples</h2>
<pre>curl -X POST https://utils.bigfloppy.net/v1/csv2json --data-binary $'a,b\\n1,2'
curl -X POST "https://utils.bigfloppy.net/v1/hash?algo=sha256" -d hello
curl https://utils.bigfloppy.net/v1/uuid?n=3</pre>
<h2>Use it as an MCP server</h2><p>Same tools (AI-slop score, csv2json, json2csv, hash, slug, wordcount, uuid, time) over <b>streamable-http MCP</b>: point any MCP client at <code>https://utils.bigfloppy.net/mcp</code> — no key needed. Listed in the official MCP registry as <code>net.bigfloppy.utils/utils</code>.</p>
<h2>Support / pay what it's worth</h2>
<p>Free tier is limited to 60 req/min per IP. If this saves you time, tip in USDC on Base: <code>%s</code> or <a href="/pay">pay by card</a>. Bigger needs (custom endpoint, higher limits)? Email the creator via the dashboard; or send USDC with a memo.</p>
</body></html>""" % WALLET

PAID = {
 "/x402/fetch":   ("Fetch a public URL and return readable plain text (HTML stripped), title, status. Max 2MB, 15s. For agents that need page text.", 5000, "GET", None),
 "/x402/csv2json":("CSV text -> JSON array of objects (no rate limit)", 1000, "POST", "text"),
 "/x402/json2csv":("JSON array -> CSV (no rate limit)", 1000, "POST", "json"),
 "/x402/hash":    ("sha256/md5/sha1/sha512 of request body (?algo=)", 1000, "POST", "text"),
 "/x402/wordcount":("words/chars/lines of text body", 1000, "POST", "text"),
"/x402/aitells":("AI-writing-tells report: score 0-99, matched tells with example sentences, style stats (em-dash rate, rule-of-three, sentence-length uniformity). Rules-based, deterministic, no LLM. Body = text to check.", 2000, "POST", "text"),
}
def _public(url):
    h = urllib.parse.urlparse(url).hostname or ""
    for ai in socket.getaddrinfo(h, None):
        ip = ipaddress.ip_address(ai[4][0])
        if not ip.is_global: return False
    return True
def fetch_text(url):
    if not url.startswith(("http://", "https://")) or not _public(url): raise ValueError("url must be public http(s)")
    r = urllib.request.urlopen(urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0 (compatible; delta-1 fetch)"}), timeout=15)
    raw = r.read(2_000_000).decode(r.headers.get_content_charset() or "utf-8", "replace")
    t = re.search(r"<title[^>]*>(.*?)</title>", raw, re.I | re.S)
    body = re.sub(r"(?is)<(script|style|noscript|svg).*?</\1>", " ", raw)
    body = re.sub(r"(?i)<br\s*/?>|</p>|</div>|</h\d>|</li>|</tr>", "\n", body)
    body = htmlmod.unescape(re.sub(r"<[^>]+>", " ", body))
    body = re.sub(r"[ \t]+", " ", body); body = re.sub(r"\n\s*\n+", "\n\n", body).strip()
    return {"url": url, "status": r.status, "title": htmlmod.unescape(t.group(1).strip()) if t else "", "text": body[:500_000]}


# --- MCP Server Card (SEP-1649 /.well-known/mcp/server-card.json + SEP-1960 /.well-known/mcp.json) ---
BASE_URL = "https://utils.bigfloppy.net/mcp"
def _server_card():
    return {
        "name": "net.bigfloppy.utils",
        "title": "Tiny Utils",
        "description": "AI-writing-tells detector (aitells, rules-based, no LLM) + csv2json, json2csv, hash, slug, wordcount, uuid, time utilities. Free, no signup.",
        "version": mcp_api.VERSION,
        "serverInfo": {"name": "net.bigfloppy.utils", "title": "Tiny Utils", "version": mcp_api.VERSION},
        "url": BASE_URL,
        "transport": {"type": "http", "url": BASE_URL},
        "protocolVersion": "2025-06-18",
        "capabilities": {"tools": {}},
        "authentication": {"type": "none"},
        "tools": [
            {"name": t["name"], "description": t["description"],
             "inputSchema": t["inputSchema"],
             "annotations": {"title": t["name"], "readOnlyHint": True, "destructiveHint": False,
                              "idempotentHint": True, "openWorldHint": False}}
            for t in mcp_api.TOOLS
        ],
    }

RATE = {}
LIMIT = 60

def ratelimited(ip):
    now = time.time(); w = int(now // 60)
    k = (ip, w); RATE[k] = RATE.get(k, 0) + 1
    for key in [k2 for k2 in RATE if k2[1] < w - 1]: RATE.pop(key, None)
    return RATE[k] > LIMIT

STATS_FILE = "usage_stats.json"
_stats_lock = __import__("threading").Lock()
def _load_stats():
    try:
        with open(STATS_FILE) as f: return json.load(f)
    except Exception: return {"paths": {}, "ips": {}}
def _count_hit(path, ip):
    import hashlib as _h
    try:
        with _stats_lock:
            st = _load_stats()
            day = time.strftime("%Y-%m-%d")
            pr = st["paths"].setdefault(path, {})
            pr[day] = pr.get(day, 0) + 1
            pip = _h.sha256(ip.encode()).hexdigest()[:16]
            ips = st["ips"].setdefault(day, [])
            if pip not in ips:
                ips.append(pip)
                if len(ips) > 10000: del ips[:5000]
            with open(STATS_FILE, "w") as f: json.dump(st, f)
    except Exception: pass

class H(BaseHTTPRequestHandler):
    def _send(self, code, body, ctype="application/json"):
        if isinstance(body, (dict, list)): body = json.dumps(body, ensure_ascii=False, indent=1)
        b = body.encode()
        self.send_response(code); self.send_header("Content-Type", ctype + "; charset=utf-8")
        self.send_header("Access-Control-Allow-Origin", "*"); self.send_header("Content-Length", str(len(b)))
        self.end_headers()
        if not getattr(self, "_head", False): self.wfile.write(b)
    def log_message(self, f, *a):
        with open("access.log", "a") as fh: fh.write("%s %s %s\n" % (time.strftime("%FT%T"), self.headers.get("X-Forwarded-For", self.client_address[0]).split(",")[0].strip(), f % a))
    def _body(self):
        n = int(self.headers.get("Content-Length") or 0)
        return self.rfile.read(min(n, 2_000_000))
    def _paid(self, p, q, raw):
        desc, amount, method, bt = PAID[p]
        ok, ver, payload, req, err = x402mw.check(self.headers, p, desc, amount, method, bt)
        if not ok:
            v2 = x402mw.reqs_v2(p, desc, amount, method, bt); v1 = x402mw.reqs_v1(p, desc, amount, method, bt)
            body = json.dumps({**v2, "error": err, "x402_v1": v1}).encode()
            self.send_response(402); self.send_header("Content-Type", "application/json")
            self.send_header("PAYMENT-REQUIRED", x402mw._b64(v2)); self.send_header("Access-Control-Allow-Origin", "*")
            self.send_header("Access-Control-Expose-Headers", "PAYMENT-REQUIRED,PAYMENT-RESPONSE,X-PAYMENT-RESPONSE")
            self.send_header("Content-Length", str(len(body))); self.end_headers(); self.wfile.write(body); return
        try:
            if p == "/x402/fetch": out = fetch_text(q.get("url", [""])[0])
            elif p == "/x402/csv2json": out = list(csv.DictReader(io.StringIO(raw.decode("utf-8-sig"))))
            elif p == "/x402/json2csv":
                data = json.loads(raw.decode()); data = [data] if isinstance(data, dict) else data
                keys = []; [keys.append(k) for r in data for k in r if k not in keys]
                o = io.StringIO(); w = csv.DictWriter(o, fieldnames=keys); w.writeheader(); w.writerows(data); out = {"csv": o.getvalue()}
            elif p == "/x402/aitells": out = aitells.analyze(raw.decode("utf-8", "replace"))
            elif p == "/x402/hash":
                algo = q.get("algo", ["sha256"])[0]; algo = algo if algo in ("md5", "sha1", "sha256", "sha512") else "sha256"
                out = {"algo": algo, "hex": hashlib.new(algo, raw).hexdigest()}
            else:
                t = raw.decode(); out = {"words": len(t.split()), "chars": len(t), "lines": t.count("\n") + (1 if t and not t.endswith("\n") else 0)}
        except Exception as e:
            return self._send(400, {"error": str(e), "note": "not charged"})
        st = x402mw.settle(ver, payload, req)
        if not st.get("success"):
            return self._send(402, {"error": "settlement failed", "detail": st.get("errorReason")})
        b = json.dumps(out, ensure_ascii=False).encode()
        self.send_response(200); self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Access-Control-Allow-Origin", "*"); self.send_header("Access-Control-Expose-Headers", "PAYMENT-RESPONSE,X-PAYMENT-RESPONSE")
        self.send_header("PAYMENT-RESPONSE" if ver == 2 else "X-PAYMENT-RESPONSE", x402mw._b64(st))
        self.send_header("Content-Length", str(len(b))); self.end_headers(); self.wfile.write(b)
    def do_HEAD(self):
        self._head = True
        try: self.do_GET()
        finally: self._head = False
    def do_OPTIONS(self):
        self.send_response(204); self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET,POST,OPTIONS"); self.send_header("Access-Control-Allow-Headers", "*"); self.end_headers()
    def do_GET(self):
        u = urllib.parse.urlparse(self.path); q = urllib.parse.parse_qs(u.query); p = u.path
        _count_hit(p, self.headers.get("X-Forwarded-For", self.client_address[0]).split(",")[0].strip())
        if p == "/": return self._send(200, INDEX, "text/html")
        if p == "/pay":
            try: link = open("paylink.txt").read().strip()
            except Exception: link = "/"
            self.send_response(302); self.send_header("Location", link); self.end_headers(); return
        if p == "/mcp": return self._send(200, {"server": "net.bigfloppy.utils", "transport": "streamable-http", "usage": "POST JSON-RPC 2.0 to /mcp", "tools": [t["name"] for t in mcp_api.TOOLS]})
        if p in PAID: return self._paid(p, q, b"")
        if ratelimited(self.client_address[0]): return self._send(429, {"error": "rate limited (60/min). Paid, unlimited x402 endpoints: /x402/*"})
        if p == "/v1/uuid":
            n = max(1, min(100, int(q.get("n", ["1"])[0]))); return self._send(200, {"uuids": [str(uuid.uuid4()) for _ in range(n)]})
        if p == "/v1/time":
            t = time.time(); return self._send(200, {"unix": int(t), "iso": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(t))})
        if p == "/v1/ip": return self._send(200, {"ip": self.headers.get("X-Forwarded-For", self.client_address[0])})
        if p == "/health": return self._send(200, {"ok": True})
        if p == "/v1/stats":
            with _stats_lock: st = _load_stats()
            out = {"paths": {}, "daily_unique_ips": {}}
            for path, days in sorted(st.get("paths", {}).items()):
                out["paths"][path] = {"total": sum(days.values()), "by_day": days}
            for day, ips in st.get("ips", {}).items():
                out["daily_unique_ips"][day] = len(ips)
            return self._send(200, out)
        if p == "/robots.txt": return self._send(200, "User-agent: *\nAllow: /\nSitemap: https://utils.bigfloppy.net/sitemap.xml\n", "text/plain")
        if p == "/favicon.ico": return self._send(200, "", "image/svg+xml")
        if p == "/favicon.svg": return self._send(200, '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 100 100"><text y=".9em" font-size="90">🧪</text></svg>', "image/svg+xml")
        if p == "/sitemap.xml": return self._send(200, '<?xml version="1.0" encoding="UTF-8"?>\n<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n<url><loc>https://utils.bigfloppy.net/</loc></url>\n<url><loc>https://utils.bigfloppy.net/v1/aitells</loc></url>\n<url><loc>https://utils.bigfloppy.net/v1/csv2json</loc></url>\n<url><loc>https://utils.bigfloppy.net/v1/json2csv</loc></url>\n<url><loc>https://utils.bigfloppy.net/v1/uuid</loc></url>\n<url><loc>https://utils.bigfloppy.net/v1/hash</loc></url>\n<url><loc>https://utils.bigfloppy.net/v1/slug</loc></url>\n<url><loc>https://utils.bigfloppy.net/v1/wordcount</loc></url>\n</urlset>', "application/xml")
        if p in ("/.well-known/mcp/server-card.json", "/.well-known/mcp.json"):
            self.send_response(200); self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Access-Control-Allow-Origin", "*"); self.send_header("Cache-Control", "public, max-age=86400")
            b = json.dumps(_server_card(), ensure_ascii=False, indent=1).encode()
            self.send_header("Content-Length", str(len(b))); self.end_headers()
            if not getattr(self, "_head", False): self.wfile.write(b)
            return
        if p.startswith("/.well-known/"):
            import os as _os
            fn = _os.path.join(_os.path.dirname(_os.path.abspath(__file__)), ".well-known", p.replace("/.well-known/", ""))
            if _os.path.isfile(fn) and "/" not in p.replace("/.well-known/", ""):
                return self._send(200, open(fn, "rb").read().decode(), "application/octet-stream")
        self._send(404, {"error": "not found", "docs": "/"})
    def do_POST(self):
        u = urllib.parse.urlparse(self.path); q = urllib.parse.parse_qs(u.query); p = u.path
        ipf = self.headers.get("X-Forwarded-For", self.client_address[0]).split(",")[0].strip()
        _count_hit(p, ipf)
        if p in PAID: return self._paid(p, q, self._body())
        if p == "/mcp":
            raw = self._body()
            method = "?"; tool = None
            try:
                req = json.loads(raw.decode("utf-8"))
                if isinstance(req, dict):
                    method = str(req.get("method") or "?")
                    if method == "tools/call":
                        tool = str(((req.get("params") or {}).get("name")) or "?")
            except Exception: pass
            _count_hit("/mcp:" + method, ipf)
            if tool: _count_hit("/tool:" + tool, ipf)
            auth = self.headers.get("Authorization") or ""
            key = self.headers.get("X-Api-Key") or (auth[7:] if auth.startswith("Bearer ") else None) or q.get("key", [None])[0]
            code, obj = mcp_api.handle(raw, key=key, ip=self.client_address[0])
            if code == 202:
                self.send_response(202); self.send_header("Content-Length", "0"); self.end_headers(); return
            return self._send(code, obj)
        if ratelimited(self.client_address[0]): return self._send(429, {"error": "rate limited (60/min)"})
        raw = self._body()
        try:
            if p == "/v1/csv2json":
                rows = list(csv.DictReader(io.StringIO(raw.decode("utf-8-sig")))); return self._send(200, rows)
            if p == "/v1/json2csv":
                data = json.loads(raw.decode())
                if isinstance(data, dict): data = [data]
                keys = []; [keys.append(k) for r in data for k in r if k not in keys]
                out = io.StringIO(); w = csv.DictWriter(out, fieldnames=keys); w.writeheader(); w.writerows(data)
                return self._send(200, out.getvalue(), "text/csv")
            if p == "/v1/hash":
                algo = q.get("algo", ["sha256"])[0]
                if algo not in ("md5", "sha1", "sha256", "sha512"): return self._send(400, {"error": "algo must be md5|sha1|sha256|sha512"})
                return self._send(200, {"algo": algo, "hex": hashlib.new(algo, raw).hexdigest(), "base64": base64.b64encode(hashlib.new(algo, raw).digest()).decode()})
            if p == "/v1/slug":
                s = re.sub(r"[^a-z0-9]+", "-", raw.decode().lower()).strip("-"); return self._send(200, {"slug": s})
            if p == "/v1/aitells":
                out = aitells.analyze(raw.decode("utf-8", "replace"))
                return self._send(200, {k: out[k] for k in ("score", "verdict", "words", "sentences")})
            if p == "/v1/wordcount":
                t = raw.decode(); return self._send(200, {"words": len(t.split()), "chars": len(t), "lines": t.count("\n") + (1 if t and not t.endswith("\n") else 0)})
        except Exception as e:
            return self._send(400, {"error": str(e)})
        self._send(404, {"error": "not found", "docs": "/"})

if __name__ == "__main__":
    ThreadingHTTPServer(("0.0.0.0", int(os.environ.get("PORT", "8311"))), H).serve_forever()
