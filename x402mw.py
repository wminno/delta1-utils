"""Minimal x402 (v1 + v2) paywall helper. Facilitator: PayAI (free tier, no key needed)."""
import json, base64, urllib.request, time, os

FACILITATOR = "https://facilitator.payai.network"
USDC_BASE = "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913"
PAY_TO = "0xdbfdF15Fe0Acad2828Bc98d6c83d6855593fcd77"
HOST = os.environ.get("X402_HOST", "http://176.124.255.233.nip.io:8311")
SERVICE = "delta-1 utils"

def _b64(o): return base64.b64encode(json.dumps(o, separators=(",", ":")).encode()).decode()
def _unb64(s): return json.loads(base64.b64decode(s + "=" * (-len(s) % 4)))

def _post(path, obj):
    req = urllib.request.Request(FACILITATOR + path, data=json.dumps(obj).encode(),
                                 headers={"Content-Type": "application/json", "User-Agent": "delta-1-x402/1"})
    with urllib.request.urlopen(req, timeout=40) as r:
        return json.loads(r.read().decode()), dict(r.headers)

def reqs_v2(path, desc, amount, method, body_type):
    bazaar_info = {"input": {"type": "http", "method": method, **({"bodyType": body_type} if body_type else {})},
                   "output": {"type": "json"}}
    schema = {"type": "object", "required": ["input", "output"], "properties": {
        "input": {"type": "object", "required": ["type", "method"], "properties": {
            "type": {"type": "string"}, "method": {"type": "string"}, "bodyType": {"type": "string"}}},
        "output": {"type": "object", "required": ["type"], "properties": {"type": {"type": "string"}}}}}
    return {
        "x402Version": 2, "error": "PAYMENT-SIGNATURE header is required",
        "resource": {"url": HOST + path, "description": desc, "mimeType": "application/json",
                     "serviceName": SERVICE, "tags": ["utility", "csv", "json", "hash", "text"]},
        "accepts": [{"scheme": "exact", "network": "eip155:8453", "amount": str(amount), "asset": USDC_BASE,
                     "payTo": PAY_TO, "maxTimeoutSeconds": 120, "extra": {"name": "USD Coin", "version": "2"}}],
        "extensions": {"bazaar": {"info": bazaar_info, "schema": schema}},
    }

def reqs_v1(path, desc, amount, method, body_type):
    return {"x402Version": 1, "error": "X-PAYMENT header is required", "accepts": [{
        "scheme": "exact", "network": "base", "maxAmountRequired": str(amount), "resource": HOST + path,
        "description": desc, "mimeType": "application/json", "payTo": PAY_TO, "maxTimeoutSeconds": 120,
        "asset": USDC_BASE, "extra": {"name": "USD Coin", "version": "2"},
        "outputSchema": {"input": {"type": "http", "method": method, **({"bodyType": body_type} if body_type else {}),
                                   "discoverable": True}, "output": {"type": "json"}}}]}

def check(headers, path, desc, amount, method, body_type):
    """Returns (ok, version, payload, requirement, err)."""
    v2 = headers.get("PAYMENT-SIGNATURE"); v1 = headers.get("X-PAYMENT")
    if not v2 and not v1: return False, 0, None, None, "payment required"
    try:
        if v2:
            payload = _unb64(v2); req = reqs_v2(path, desc, amount, method, body_type)["accepts"][0]; ver = 2
            acc = payload.get("accepted", {})
            if acc.get("network") != req["network"] or acc.get("payTo", "").lower() != PAY_TO.lower() or int(acc.get("amount", 0)) < amount:
                return False, 2, None, None, "accepted requirement mismatch"
        else:
            payload = _unb64(v1); req = reqs_v1(path, desc, amount, method, body_type)["accepts"][0]; ver = 1
            if payload.get("network") != "base" or payload.get("scheme") != "exact":
                return False, 1, None, None, "network/scheme mismatch"
        res, _ = _post("/verify", {"x402Version": ver, "paymentPayload": payload, "paymentRequirements": req})
        if not res.get("isValid"): return False, ver, None, None, "verify failed: %s" % res.get("invalidReason")
        return True, ver, payload, req, None
    except Exception as e:
        return False, 0, None, None, "payment error: %s" % e

def settle(ver, payload, req):
    try:
        res, _ = _post("/settle", {"x402Version": ver, "paymentPayload": payload, "paymentRequirements": req})
    except Exception as e:
        res = {"success": False, "errorReason": str(e), "transaction": "", "network": "eip155:8453"}
    with open("payments.log", "a") as f: f.write("%s %s\n" % (time.strftime("%FT%T"), json.dumps(res)))
    return res
