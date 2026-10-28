import json, time, csv, io, hashlib, uuid as _uuid, urllib.parse
import aitells
import mcpscan

VERSION = "1.0.2"
RATE = {}

def _rl(ip):
    now = time.time(); w = int(now // 60); k = (ip, w)
    RATE[k] = RATE.get(k, 0) + 1
    for key in [k2 for k2 in RATE if k2[1] < w - 1]: RATE.pop(key, None)
    return RATE[k] > 30

def _slug(s): return re_slug(s)
def re_slug(s): import re as _re; return _re.sub(r"[^a-z0-9]+", "-", s.lower()).strip("-")

TOOLS = [
 {"name": "aitells", "description": "AI-writing-tells score 0-99 with verdict, word/sentence counts. Rules-based, deterministic, no LLM. Input: text to check.", "inputSchema": {"type": "object", "properties": {"text": {"type": "string", "description": "text to analyze"}}, "required": ["text"]}},
 {"name": "aitells_report", "description": "Full AI-writing-tells report: score, every matched tell with example sentences, style stats (em-dash rate, rule-of-three, sentence-length uniformity). Deterministic, no LLM.", "inputSchema": {"type": "object", "properties": {"text": {"type": "string", "description": "text to analyze"}}, "required": ["text"]}},
 {"name": "csv2json", "description": "Convert CSV text to a JSON array of objects (first row = headers).", "inputSchema": {"type": "object", "properties": {"csv": {"type": "string", "description": "CSV text"}}, "required": ["csv"]}},
 {"name": "json2csv", "description": "Convert a JSON array of objects to CSV text.", "inputSchema": {"type": "object", "properties": {"json": {"type": "string", "description": "JSON array (or single object) as a string"}}, "required": ["json"]}},
 {"name": "hash", "description": "Hash text with md5, sha1, sha256 or sha512 (default sha256).", "inputSchema": {"type": "object", "properties": {"text": {"type": "string"}, "algo": {"type": "string", "enum": ["md5", "sha1", "sha256", "sha512"]}}, "required": ["text"]}},
 {"name": "slug", "description": "Turn text into a URL slug.", "inputSchema": {"type": "object", "properties": {"text": {"type": "string"}}, "required": ["text"]}},
 {"name": "wordcount", "description": "Count words, characters and lines of text.", "inputSchema": {"type": "object", "properties": {"text": {"type": "string"}}, "required": ["text"]}},
 {"name": "uuid", "description": "Generate random UUIDv4s (1-100, default 5).", "inputSchema": {"type": "object", "properties": {"n": {"type": "integer", "minimum": 1, "maximum": 100}}, "required": []}},
 {"name": "trust_scan", "description": "MCP Server Trust Scan: audit any public MCP server (card fields, handshake, tools/list, HEAD, auth posture, hygiene leaks). Deterministic score 0-100 + grade + per-check report. Input: url of the server or its /mcp endpoint.", "inputSchema": {"type": "object", "properties": {"url": {"type": "string", "description": "https URL of the MCP server or its /mcp endpoint"}, "deep": {"type": "boolean", "description": "include hygiene probes (default true)"}}, "required": ["url"]}},
 {"name": "time", "description": "Current unix + ISO UTC time.", "inputSchema": {"type": "object", "properties": {}, "required": []}},
]

def _txt(v): return v if isinstance(v, str) else json.dumps(v)

def _call(name, a):
    if name in ("aitells", "aitells_report"):
        out = aitells.analyze(a.get("text", "").encode().decode("utf-8", "replace"))
        if name == "aitells": out = {k: out[k] for k in ("score", "verdict", "words", "sentences")}
        return {"content": [{"type": "text", "text": json.dumps(out, ensure_ascii=False)}]}
    if name == "csv2json":
        rows = list(csv.DictReader(io.StringIO(a.get("csv", "").encode().decode("utf-8-sig"))))
        return {"content": [{"type": "text", "text": json.dumps(rows, ensure_ascii=False)}]}
    if name == "json2csv":
        data = json.loads(a.get("json", "[]")); data = [data] if isinstance(data, dict) else data
        keys = []
        for r in data:
            for k in r:
                if k not in keys: keys.append(k)
        o = io.StringIO(); w = csv.DictWriter(o, fieldnames=keys); w.writeheader(); w.writerows(data)
        return {"content": [{"type": "text", "text": o.getvalue()}]}
    if name == "hash":
        algo = a.get("algo") if a.get("algo") in ("md5", "sha1", "sha256", "sha512") else "sha256"
        h = hashlib.new(algo, a.get("text", "").encode())
        return {"content": [{"type": "text", "text": json.dumps({"algo": algo, "hex": h.hexdigest(), "base64": base64_b64(h)})}]}
    if name == "slug":
        return {"content": [{"type": "text", "text": json.dumps({"slug": re_slug(a.get("text", ""))})}]}
    if name == "wordcount":
        t = a.get("text", "")
        return {"content": [{"type": "text", "text": json.dumps({"words": len(t.split()), "chars": len(t), "lines": t.count("\n") + (1 if t and not t.endswith("\n") else 0)})}]}
    if name == "uuid":
        n = max(1, min(100, int(a.get("n", 5) or 5)))
        return {"content": [{"type": "text", "text": json.dumps({"uuids": [str(_uuid.uuid4()) for _ in range(n)]})}]}
    if name == "trust_scan":
        try:
            out = mcpscan.scan(a.get("url", ""), deep=bool(a.get("deep", True)))
        except Exception as e:
            out = {"error": str(e)}
        return {"content": [{"type": "text", "text": json.dumps(out, ensure_ascii=False)}]}
    if name == "time":
        t = time.time()
        return {"content": [{"type": "text", "text": json.dumps({"unix": int(t), "iso": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(t))})}]}
    raise ValueError("unknown tool")

def base64_b64(h):
    import base64; return base64.b64encode(h.digest()).decode()

def handle(raw, key=None, ip="0.0.0.0"):
    try:
        req = json.loads(raw.decode("utf-8"))
    except Exception:
        return 400, {"jsonrpc": "2.0", "id": None, "error": {"code": -32700, "message": "parse error"}}
    m = req.get("method"); rid = req.get("id"); p = req.get("params") or {}
    if m == "initialize":
        return 200, {"jsonrpc": "2.0", "id": rid, "result": {"protocolVersion": p.get("protocolVersion", "2025-06-18"), "capabilities": {"tools": {}}, "serverInfo": {"name": "net.bigfloppy.utils", "version": VERSION, "title": "Tiny Utils", "description": "AI-writing-tells detector + CSV/JSON, hash, slug, wordcount, UUID utilities. Free, no signup; rules-based, no LLM.", "websiteUrl": "https://utils.bigfloppy.net/"}, "instructions": "Call tools/list, then tools/call. aitells = quick AI-slop score; aitells_report = full tell-by-tell report."}}
    if m == "notifications/initialized":
        return 202, None
    if m == "ping":
        return 200, {"jsonrpc": "2.0", "id": rid, "result": {}}
    if m == "tools/list":
        return 200, {"jsonrpc": "2.0", "id": rid, "result": {"tools": TOOLS}}
    if m == "tools/call":
        name = p.get("name"); a = p.get("arguments") or {}
        if _rl(ip): return 429, {"jsonrpc": "2.0", "id": rid, "error": {"code": -32000, "message": "rate limited (30/min per IP)"}}
        try:
            out = _call(name, a)
        except Exception as e:
            return 200, {"jsonrpc": "2.0", "id": rid, "result": {"isError": True, "content": [{"type": "text", "text": "error: " + str(e)}]}}
        return 200, {"jsonrpc": "2.0", "id": rid, "result": out}
    return 404, {"jsonrpc": "2.0", "id": rid, "error": {"code": -32601, "message": "method not found: " + str(m)}}
