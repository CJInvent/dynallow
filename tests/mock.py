"""Test doubles: IP-lookup service, Cloudflare API, PowerDNS API, dyndns2, DuckDNS, and an SMTP sink.
State lives in memory and is inspectable via GET /_state; tests steer it via POST /_set."""
import json, threading, socketserver, sys, re
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

STATE = {"ip4": "203.0.113.10", "ip6": "", "cf": {}, "pdns": {"example.org.": {}}, "dyn": [], "duck": [], "mail": [],
         "cf_fail": False, "pdns_fail": False, "calls": []}
LOCK = threading.Lock()

class H(BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def _send(self, code, body, ctype="application/json"):
        b = body if isinstance(body, bytes) else (body if isinstance(body, str) else json.dumps(body)).encode()
        self.send_response(code); self.send_header("Content-Type", ctype); self.send_header("Content-Length", str(len(b))); self.end_headers()
        if b: self.wfile.write(b)
    def _body(self):
        n = int(self.headers.get("Content-Length") or 0)
        return json.loads(self.rfile.read(n) or b"null") if n else None
    def do_GET(self): self.route("GET")
    def do_POST(self): self.route("POST")
    def do_PATCH(self): self.route("PATCH")
    def do_PUT(self): self.route("PUT")
    def do_DELETE(self): self.route("DELETE")
    def route(self, m):
        u = urlparse(self.path); q = parse_qs(u.query); p = u.path
        with LOCK: STATE["calls"].append(f"{m} {p}")
        if p == "/_state": return self._send(200, {k: v for k, v in STATE.items() if k != "calls"} | {"calls": STATE["calls"][-50:]})
        if p == "/_set":
            with LOCK: STATE.update(self._body() or {})
            return self._send(200, {"ok": True})
        if p == "/ip": return self._send(200, STATE["ip4"] + "\n", "text/plain")
        if p == "/ip6": return self._send(200 if STATE["ip6"] else 503, STATE["ip6"], "text/plain")
        # --- Cloudflare ---
        if p.startswith("/cf/"):
            if self.headers.get("Authorization") != "Bearer cf-good-token":
                return self._send(403, {"success": False, "errors": [{"message": "Invalid API Token"}]})
            if p == "/cf/user/tokens/verify": return self._send(200, {"success": True, "result": {"status": "active"}})
            if p == "/cf/zones":
                n = q.get("name", [""])[0]
                return self._send(200, {"success": True, "result": [{"id": "zone1"}] if n == "example.com" else []})
            mm = re.match(r"^/cf/zones/zone1/dns_records(?:/(\w+))?$", p)
            if mm:
                if STATE["cf_fail"]: return self._send(500, {"success": False, "errors": [{"message": "simulated outage"}]})
                rid = mm.group(1)
                if m == "GET":
                    name = q.get("name", [""])[0]
                    recs = [r for r in STATE["cf"].values() if r["name"] == name]
                    return self._send(200, {"success": True, "result": recs})
                if m == "DELETE":
                    with LOCK: STATE["cf"].pop(rid, None)
                    return self._send(200, {"success": True, "result": {"id": rid}})
                b = self._body()
                with LOCK:
                    if m == "POST":
                        rid = "r%d" % (len(STATE["cf"]) + 1); STATE["cf"][rid] = dict(b, id=rid)
                    else:
                        STATE["cf"][rid].update(b)
                return self._send(200, {"success": True, "result": STATE["cf"][rid]})
        # --- PowerDNS ---
        if p.startswith("/pdns/api/v1/"):
            if self.headers.get("X-API-Key") != "pdns-key":
                return self._send(401, {"error": "Unauthorized"})
            if p == "/pdns/api/v1/servers/localhost": return self._send(200, {"version": "4.9.0-mock", "daemon_type": "authoritative"})
            if p == "/pdns/api/v1/servers/localhost/zones":
                return self._send(200, [{"id": z, "name": z} for z in STATE["pdns"]])
            mm = re.match(r"^/pdns/api/v1/servers/localhost/zones/([^/]+)(/notify)?$", p)
            if mm:
                from urllib.parse import unquote
                z = unquote(mm.group(1))
                if z not in STATE["pdns"]: return self._send(404, {"error": "Could not find domain"})
                if mm.group(2): return self._send(200, {"result": "Notification queued"})
                if m == "GET":
                    rr = [{"name": n, "type": "A", "ttl": 60, "records": [{"content": c, "disabled": False}]} for n, c in STATE["pdns"][z].items()]
                    return self._send(200, {"name": z, "rrsets": rr})
                if m == "PATCH":
                    if STATE["pdns_fail"]: return self._send(422, {"error": "simulated failure"})
                    for rr in self._body()["rrsets"]:
                        if rr["type"] != "A" or rr["changetype"] not in ("REPLACE", "DELETE"):
                            return self._send(422, {"error": "unsupported rrset change"})
                        with LOCK:
                            if rr["changetype"] == "DELETE": STATE["pdns"][z].pop(rr["name"], None)
                            else: STATE["pdns"][z][rr["name"]] = rr["records"][0]["content"]
                    return self._send(204, b"")
        # --- dyndns2 / duckdns ---
        if p == "/nic/update":
            with LOCK: STATE["dyn"].append({"q": q, "auth": self.headers.get("Authorization"), "ua": self.headers.get("User-Agent")})
            return self._send(200, ("good " + q["myip"][0]) if self.headers.get("Authorization") else "badauth", "text/plain")
        if p == "/update":
            with LOCK: STATE["duck"].append(q)
            return self._send(200, "OK" if q.get("token", [""])[0] == "duck-token" else "KO", "text/plain")
        return self._send(404, {"error": "no route " + p})

class SMTP(socketserver.StreamRequestHandler):
    def handle(self):
        w = lambda s: self.wfile.write((s + "\r\n").encode())
        w("220 mock ESMTP"); data = None; msg = {"rcpt": []}
        while True:
            line = self.rfile.readline().decode(errors="replace")
            if not line: return
            if data is not None:
                if line.rstrip("\r\n") == ".":
                    msg["data"] = "".join(data); 
                    with LOCK: STATE["mail"].append(msg)
                    data = None; msg = {"rcpt": []}; w("250 queued"); continue
                data.append(line); continue
            c = line.strip().upper()
            if c.startswith("EHLO"): self.wfile.write(b"250-mock\r\n250 AUTH LOGIN\r\n")
            elif c.startswith("MAIL"): w("250 ok")
            elif c.startswith("RCPT"): msg["rcpt"].append(line.strip()[8:]); w("250 ok")
            elif c == "DATA": data = []; w("354 go")
            elif c == "QUIT": w("221 bye"); return
            else: w("250 ok")

if __name__ == "__main__":
    port = int(sys.argv[1]); smtp_port = int(sys.argv[2])
    socketserver.ThreadingTCPServer.allow_reuse_address = True
    threading.Thread(target=socketserver.ThreadingTCPServer(("127.0.0.1", smtp_port), SMTP).serve_forever, daemon=True).start()
    ThreadingHTTPServer(("0.0.0.0", port), H).serve_forever()
