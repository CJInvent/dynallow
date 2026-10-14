"""End-to-end: real agents installed from UI-downloaded installers, then the whole lifecycle."""
import sys, os, re, json, time, sqlite3, subprocess, hmac, hashlib, struct, base64, shutil, urllib.request
T = sys.argv[1]; S = os.path.dirname(T)
sys.path.insert(0, T); from web import Browser, flashes
SRV = S + "/srv"; DB = SRV + "/data/ipfailover.sqlite"; PW = os.environ.get("PWSH", "pwsh")
WIN = S + "/winprog"; WDATA = S + "/windata"; DOCK = S + "/dock"
GW = open(T + "/gw").read().strip()
ok = bad = 0
def check(cond, msg, extra=""):
    global ok, bad
    if cond: ok += 1; print("  PASS", msg)
    else: bad += 1; print("  FAIL", msg, extra)
def section(s): print("\n==", s)
def q(sql, *a):
    c = sqlite3.connect(DB, timeout=10); c.row_factory = sqlite3.Row
    r = [dict(x) for x in c.execute(sql, a)]; c.commit(); c.close(); return r
def x(sql, *a):
    c = sqlite3.connect(DB, timeout=10); c.execute(sql, a); c.commit(); c.close()
def mock(path="/_state", data=None):
    r = urllib.request.Request("http://127.0.0.1:8099" + path, data=json.dumps(data).encode() if data else None, method="POST" if data else "GET")
    return json.load(urllib.request.urlopen(r))
def subjects(): return [l for m in mock()["mail"] for l in m["data"].splitlines() if l.startswith("Subject:")]
def remote(ip): open(SRV + "/fake_remote", "w").write(ip)
def cron(): return subprocess.run(["php", SRV + "/bin/cron.php", "-v"], capture_output=True, text=True, timeout=120).stdout
def run_win(timeout=90):
    env = {k: v for k, v in os.environ.items() if k.lower() not in ("http_proxy", "https_proxy", "all_proxy")}
    env["NO_PROXY"] = env["no_proxy"] = "*"   # the sandbox's egress proxy would otherwise sit between agent and server
    r = subprocess.run([PW, "-NoProfile", "-File", WIN + "/ip-agent.ps1", "-DataDir", WDATA, "-Once"], capture_output=True, text=True, timeout=timeout, env=env)
    return r.returncode, r.stdout + r.stderr
def dock_cycle(wait=12):
    subprocess.run(["docker", "restart", "ipfailover-agent"], capture_output=True, timeout=60); time.sleep(wait)
def dock_health():
    r = subprocess.run(["docker", "exec", "ipfailover-agent", "php", "/app/agent.php", "health"], capture_output=True, text=True, timeout=30)
    return r.returncode, r.stdout.strip()
def agent(aid): return q("SELECT * FROM agents WHERE id = ?", aid)[0]
def totp(secret_b32, t=None):
    key = base64.b32decode(secret_b32.replace(" ", "")); step = int((t or time.time()) // 30)
    h = hmac.new(key, struct.pack(">Q", step), hashlib.sha1).digest(); o = h[19] & 15
    return "%06d" % ((struct.unpack(">I", h[o:o + 4])[0] & 0x7fffffff) % 1000000)

ids = json.load(open(T + "/ids.json")); WIN_ID = int(ids["win"]); DOCK_ID = int(ids["docker"]); RHOST = ids["random_host"]
b = Browser(); b.get("login.php"); b.post("login.php", {"username": "admin", "password": "correct-horse-battery"})
b.get("settings.php")
b.post("settings.php", {"action": "save", "section": "General", "public_url": f"http://{GW}:8088", "timezone": "America/Chicago",
    "default_interval_sec": "60", "default_missed": "2", "ip_check_urls": f"http://{GW}:8099/ip", "ip_confirm_checkins": "1"})

# ---------------------------------------------------------------- Windows installer
section("Windows one-file installer from the UI")
b.get(f"agent.php?id={WIN_ID}")
code, body, hdr = b.post("profile.php", {"id": WIN_ID, "format": "windows"}, follow=False)
check(code == 200 and "attachment" in hdr.get("Content-Disposition", ""), "installer downloads as an attachment")
check("no-store" in hdr.get("Cache-Control", ""), "profile download is no-store")
inst = T + "/Install.ps1"; open(inst, "w").write(body)
helper = T + "/extract.ps1"
open(helper, "w").write(r'''param($f)
$e=$null;$t=$null; $ast=[Management.Automation.Language.Parser]::ParseFile($f,[ref]$t,[ref]$e)
if ($e.Count) { "PARSE-ERRORS: $($e.Count)"; exit 1 }
$a=$ast.FindAll({ $args[0] -is [Management.Automation.Language.AssignmentStatementAst] -and $args[0].Left.Extent.Text -eq '$Embedded' }, $true) | Select-Object -First 1
$h = Invoke-Expression $a.Right.Extent.Text
$out=@{}; foreach ($k in $h.Keys) { $b=[Convert]::FromBase64String($h[$k]); $out[$k]=[BitConverter]::ToString([Security.Cryptography.SHA256]::Create().ComputeHash($b)).Replace('-','').ToLower(); if ($k -eq 'provisioning.json') { $out['_profile']=[Text.Encoding]::UTF8.GetString($b) } }
$out | ConvertTo-Json -Compress''')
r = subprocess.run([PW, "-NoProfile", "-File", helper, inst], capture_output=True, text=True)
emb = json.loads(r.stdout)
src = SRV + "/agents/windows/"
same = all(emb[f] == hashlib.sha256(open(src + f, "rb").read()).hexdigest() for f in ["run-agent.ps1", "ip-agent.ps1", "ip-agent-tray.ps1", "uninstall.ps1"])
check(same, "installer parses with the real PowerShell parser and embeds the exact agent files")
prof = json.loads(emb["_profile"])
check(prof["control_url"] == f"http://{GW}:8088" and len(base64.b64decode(prof["server_key"])) == 65, "embedded profile pins the server URL and key")
row = agent(WIN_ID)
check(row["enroll_token_hash"] == hashlib.sha256(prof["enroll_token"].encode()).hexdigest(), "server stores only the token's SHA-256")
check(prof["enroll_token"] not in open(DB, "rb").read().decode("latin-1"), "plaintext token is nowhere in the database")
# second download voids the first
code, body2, _ = b.post("profile.php", {"id": WIN_ID, "format": "json"}, follow=False)
prof2 = json.loads(body2)
check(prof2["enroll_token"] != prof["enroll_token"], "each download mints a new token")

section("Install the Windows agent (simulated Program Files + ProgramData) and enroll")
shutil.rmtree(WIN, True); shutil.rmtree(WDATA, True); os.makedirs(WIN); os.makedirs(WDATA)
for f in ["run-agent.ps1", "ip-agent.ps1", "ip-agent-tray.ps1", "uninstall.ps1"]: shutil.copy(src + f, WIN)
open(WDATA + "/provisioning.json", "w").write(json.dumps(prof))   # the voided one first
mock("/_set", {"ip4": "203.0.113.50"}); remote("203.0.113.50")
rc, out = run_win()
check("provisioning token is not valid" in out, "a voided (superseded) profile is refused", out[-300:])
check(not os.path.exists(WDATA + "/provisioning.json"), "the profile file is destroyed even when it fails")
os.remove(WDATA + "/state.json")
open(WDATA + "/provisioning.json", "w").write(json.dumps(prof2))
rc, out = run_win(); rc, out = run_win()
row = agent(WIN_ID)
check(row["pubkey"] and row["current_ipv4"] == "203.0.113.50" and row["ip_source"] == "verified", "enrolled; IP verified by agent + connection", out[-400:])
cf = {r["name"]: r["content"] for r in mock()["cf"].values()}
pd = mock()["pdns"]["example.org."]
check(cf.get(RHOST) == "203.0.113.50", f"Cloudflare random name {RHOST} created server-side")
check(pd.get("smith-pbx.example.org.") == "203.0.113.50", "PowerDNS record set server-side")
st = json.load(open(WDATA + "/public/status.json"))
check(st["server_ok"] and len(st["targets"]) == 2 and all(t["state"] == "ok" for t in st["targets"]), "tray status file shows server OK and both DNS names OK")
for secret in ("agent-key.json", "master.key", "state.json"):
    check(not os.path.exists(WDATA + "/public/" + secret), f"{secret} is not in the user-readable folder")
keyrec = json.load(open(WDATA + "/agent-key.json"))
check(keyrec["active"]["sealed"].startswith("sv1:") and "private" not in json.dumps(keyrec).lower().replace("protector", ""), "private key is sealed under the DEK on disk")

# ---------------------------------------------------------------- attacks on the wire
section("Attacks on the agent channel (plain HTTP)")
remote("192.0.2.99")   # a relay: the request arrives from somewhere the agent isn't
rc, out = run_win()
a = agent(WIN_ID); cf = {r["name"]: r["content"] for r in mock()["cf"].values()}
check(a["ip_mismatch"] == 1 and a["current_ipv4"] == "203.0.113.50" and cf.get(RHOST) == "203.0.113.50", "relayed request: IP held, DNS untouched", out[-200:])
remote("203.0.113.50"); run_win()
check(agent(WIN_ID)["ip_mismatch"] == 0, "corroboration restored when the path is clean again")
open(SRV + "/capture", "w").close(); run_win(); os.remove(SRV + "/capture")
n = agent(WIN_ID)["checkin_count"]
urllib.request.urlopen(urllib.request.Request("http://127.0.0.1:8088/api/v1.php", data=open(SRV + "/captured.bin", "rb").read(), method="POST")).read()
check(agent(WIN_ID)["checkin_count"] == n, "replayed request rejected (nonce already seen)")
open(SRV + "/tamper", "w").close(); rc, out = run_win(); os.remove(SRV + "/tamper")
check(rc != 0 and "failed authentication" in out, "one flipped bit in a response: agent ignores it")
FORGE = S + "/forge"; shutil.rmtree(FORGE, True); shutil.copytree(WDATA, FORGE)
for f in ("agent-key.json", "master.key"): os.remove(FORGE + "/" + f)
env = {k: v for k, v in os.environ.items() if k.lower() not in ("http_proxy", "https_proxy", "all_proxy")}; env["NO_PROXY"] = env["no_proxy"] = "*"
r = subprocess.run([PW, "-NoProfile", "-File", WIN + "/ip-agent.ps1", "-DataDir", FORGE, "-Once"], capture_output=True, text=True, timeout=90, env=env)
check("bad_signature" in r.stdout and any("Forged request for SmithDental-PBX" in s for s in subjects()), "attacker using the agent's ID with their own key: rejected + emailed")

if os.environ.get("STOP_AFTER") == "attacks":
    print(f"\n{ok} passed, {bad} failed"); sys.exit(1 if bad else 0)
# ---------------------------------------------------------------- Docker installer
section("Docker one-file installer from the UI, run for real")
subprocess.run(["docker", "rm", "-f", "ipfailover-agent"], capture_output=True)
shutil.rmtree(DOCK, True)
b.get(f"agent.php?id={DOCK_ID}")
code, body, hdr = b.post("profile.php", {"id": DOCK_ID, "format": "docker"}, follow=False)
sh = T + "/install-docker.sh"; open(sh, "w").write(body)
check(subprocess.run(["sh", "-n", sh]).returncode == 0, "Docker installer is valid shell")
remote("198.51.100.77")   # docker site is in trust mode "server": the server-seen address wins
r = subprocess.run(["sh", sh], capture_output=True, text=True, env={**os.environ, "IPF_DIR": DOCK}, timeout=240)
print("   ", r.stdout.strip().splitlines()[-1] if r.stdout.strip() else r.stderr[-300:])
check(not os.path.exists(sh), "Docker installer deleted itself (it held a credential)")
check(not os.path.exists(DOCK + "/data/provisioning.json"), "profile consumed and destroyed inside the container")
insp = json.loads(subprocess.run(["docker", "inspect", "ipfailover-agent"], capture_output=True, text=True).stdout)[0]
hc = insp["HostConfig"]
check(insp["Config"]["User"] == "65534:65534" and hc["ReadonlyRootfs"] and hc["CapDrop"] == ["ALL"], "container runs as nobody, read-only root, all capabilities dropped")
rc, hmsg = dock_health()
row = agent(DOCK_ID)
check(row["pubkey"] and row["current_ipv4"] == "198.51.100.77" and row["key_protector"] == "container-file", "Docker agent enrolled; key custody reported honestly", hmsg)
dyn = mock()["dyn"]
check(dyn and dyn[-1]["q"]["myip"] == ["198.51.100.77"] and dyn[-1]["q"]["hostname"] == ["other.ddns.net"], "dyndns2 update sent server-side with myip")
check(dyn and dyn[-1]["auth"] and dyn[-1]["ua"].startswith("ipfailover-control/"), "dyndns2 uses basic auth + identifying User-Agent")
check(rc == 0 and "HEALTHY" in hmsg, f"container healthcheck: {hmsg}")

# ---------------------------------------------------------------- cron: missed check-ins
section("Missed check-ins -> OFFLINE email -> RECOVERED email")
x("UPDATE agents SET last_checkin_at = ? WHERE id = ?", int(time.time()) - 600, WIN_ID)
out = cron()
check(agent(WIN_ID)["alert_state"] == "missed" and any("OFFLINE: SmithDental-PBX missed 2" in s for s in subjects()), "two missed check-ins -> OFFLINE email")
check(agent(DOCK_ID)["alert_state"] == "ok", "the healthy site is not alerted")
c, t, h = b.get("index.php")
check("Offline" in t and "badge bad" in t, "dashboard shows the site as Offline (red)")
rc, out = run_win()
check(agent(WIN_ID)["alert_state"] == "ok" and any("RECOVERED: SmithDental-PBX" in s for s in subjects()), "check-in clears it -> RECOVERED email")
hooks = [c for c in mock()["calls"] if c == "POST /hook"]
check(len(hooks) >= 2, "alerts are mirrored to the webhook")

# ---------------------------------------------------------------- drift
section("DNS drift (record changed behind our back) -> repaired + email")
st = mock()
rid = [k for k, v in st["cf"].items() if v["name"] == RHOST][0]
mock("/_set", {"cf": {**st["cf"], rid: {**st["cf"][rid], "content": "6.6.6.6"}}})
x("UPDATE dns_targets SET last_verified_at = 0")
out = cron()
cf = {r["name"]: r["content"] for r in mock()["cf"].values()}
check(cf[RHOST] == "203.0.113.50" and any("DNS DRIFT" in s for s in subjects()), "drift detected via API, record restored, email sent", out)

# ---------------------------------------------------------------- DNS failure
section("Provider failure -> retries with backoff -> alert -> recovery")
mock("/_set", {"pdns_fail": True, "ip4": "203.0.113.51"}); remote("203.0.113.51")
rc, out = run_win()
t = q("SELECT * FROM dns_targets WHERE hostname = 'smith-pbx.example.org'")[0]
check(t["state"] == "fault" and t["fail_count"] == 1, "push failed and was recorded (attempt 1)")
cf = {r["name"]: r["content"] for r in mock()["cf"].values()}
check(cf[RHOST] == "203.0.113.51", "the OTHER provider still updated independently")
out = cron()
check(q("SELECT fail_count FROM dns_targets WHERE id = ?", t["id"])[0]["fail_count"] == 1, "cron respects backoff (no immediate retry)")
x("UPDATE dns_targets SET last_attempt_at = 0 WHERE id = ?", t["id"]); cron()
check(any("DNS UPDATE FAILING: smith-pbx" in s for s in subjects()), "alert after 2 consecutive failures")
mock("/_set", {"pdns_fail": False}); x("UPDATE dns_targets SET last_attempt_at = 0 WHERE id = ?", t["id"]); cron()
check(mock()["pdns"]["example.org."]["smith-pbx.example.org."] == "203.0.113.51" and any("DNS RECOVERED" in s for s in subjects()), "retry succeeds -> RECOVERED email")
rc, out = run_win()
st = json.load(open(WDATA + "/public/status.json"))
check(all(t["state"] == "ok" for t in st["targets"]), "agent's tray status reflects the recovery")

# ---------------------------------------------------------------- key rotation
section("Agent key rotation (two-slot, server-promoted)")
old = agent(WIN_ID)["pubkey_id"]
b.get(f"agent.php?id={WIN_ID}"); b.post("agent.php", {"id": WIN_ID, "action": "rotate_key"})
run_win(); mid = agent(WIN_ID)
check(mid["pending_pubkey_id"] and mid["pubkey_id"] == old, "cycle 1: new key registered as pending, old key still active")
kf = json.load(open(WDATA + "/agent-key.json"))
check("pending" in kf and "active" in kf, "agent holds both slots during rotation")
run_win(); after = agent(WIN_ID)
kf = json.load(open(WDATA + "/agent-key.json"))
check(after["pubkey_id"] == mid["pending_pubkey_id"] and not after["pending_pubkey"] and "pending" not in kf, "cycle 2: server promoted on first use; agent dropped the old key")
rc, out = run_win()
check(rc == 0, "agent keeps working on the rotated key")
x("UPDATE agents SET rotate_requested = 1 WHERE id = ?", DOCK_ID); oldd = agent(DOCK_ID)["pubkey_id"]
dock_cycle(); dock_cycle()
check(agent(DOCK_ID)["pubkey_id"] != oldd and not agent(DOCK_ID)["pending_pubkey"], "Docker agent rotates too")

# ---------------------------------------------------------------- manual trust
section("Manual trust mode: IP change needs approval")
a = agent(WIN_ID)
b.get(f"agent.php?id={WIN_ID}")
b.post("agent.php", {"id": WIN_ID, "action": "save", "name": a["name"], "customer": a["customer"], "site_address": "", "site_contact": "", "tags": a["tags"], "notes": "",
    "interval_sec": "60", "missed_threshold": "2", "alert_emails": "tech@test.local", "trust_mode": "manual"})
mock("/_set", {"ip4": "203.0.113.60"}); remote("203.0.113.60")
run_win()
a = agent(WIN_ID)
check(a["current_ipv4"] == "203.0.113.51" and a["pending_ipv4"] == "203.0.113.60", "new IP held as pending, DNS unchanged")
check(any("APPROVAL NEEDED" in s for s in subjects()), "approval email sent")
c, t, h = b.get(f"agent.php?id={WIN_ID}")
check("Approve 203.0.113.60" in t, "approve button shown to admin")
b.post("agent.php", {"id": WIN_ID, "action": "approve_ip"})
cf = {r["name"]: r["content"] for r in mock()["cf"].values()}
check(agent(WIN_ID)["current_ipv4"] == "203.0.113.60" and cf[RHOST] == "203.0.113.60", "approved -> authoritative + DNS pushed immediately")
check(q("SELECT source FROM ip_history WHERE agent_id = ? ORDER BY id DESC LIMIT 1", WIN_ID)[0]["source"] == "approved", "history records it was approved")

# ---------------------------------------------------------------- feeds
section("Allowlist feed: HTTPS-only, source-restricted, signed")
saved_remote = open(SRV + "/fake_remote").read(); os.remove(SRV + "/fake_remote")   # feeds come from 127.0.0.1 directly
c, t, h = b.post("feeds.php", {"action": "add", "name": "pbx fw", "tag_filter": "pbx", "max_age_hours": "24", "allowed_sources": "127.0.0.1"})
tok = re.search(r'id="tok">([^<]+)<', t).group(1)
def feed(qs, headers=None):
    r = urllib.request.Request(f"http://127.0.0.1:8088/feed.php?{qs}", headers=headers or {})
    try: resp = urllib.request.urlopen(r); return resp.status, resp.read().decode(), resp.headers
    except urllib.error.HTTPError as e: return e.code, e.read().decode(), e.headers
code, body, _ = feed(f"token={tok}")
check(code == 403 and "HTTPS" in body, "plain-HTTP feed refused")
code, body, hd = feed(f"token={tok}", {"X-Forwarded-Proto": "https"})
check(code == 200 and body.strip() == "203.0.113.60", f"feed over HTTPS lists only the pbx-tagged site's verified IP: {body.strip()!r}")
pub = json.loads(feed("pubkey=1")[1])
open(T + "/feed.pem", "w").write(pub["public_key_pem"]); open(T + "/feed.body", "w").write(body)
sig = base64.b64decode(hd["X-IPF-Signature"]); r_, s_ = int.from_bytes(sig[:32], "big"), int.from_bytes(sig[32:], "big")
def der_int(n):
    bb = n.to_bytes((n.bit_length() + 8) // 8, "big"); return b"\x02" + bytes([len(bb)]) + bb
der = der_int(r_) + der_int(s_); open(T + "/feed.sig", "wb").write(b"\x30" + bytes([len(der)]) + der)
v = subprocess.run(["openssl", "dgst", "-sha256", "-verify", T + "/feed.pem", "-signature", T + "/feed.sig", T + "/feed.body"], capture_output=True, text=True)
check("Verified OK" in v.stdout, "feed signature verifies with stock openssl")
open(T + "/feed.body", "w").write(body.replace("60", "61"))
v = subprocess.run(["openssl", "dgst", "-sha256", "-verify", T + "/feed.pem", "-signature", T + "/feed.sig", T + "/feed.body"], capture_output=True, text=True)
check("Verification failure" in v.stdout, "a tampered feed fails verification")
code, body, _ = feed(f"token=nope", {"X-Forwarded-Proto": "https"})
check(code == 401, "unknown feed token refused")
b.post("feeds.php", {"action": "add", "name": "restricted", "tag_filter": "", "max_age_hours": "24", "allowed_sources": "10.9.9.0/24"})
code, body, _ = feed(f"token={re.search(r'id=.tok.>([^<]+)<', b.post('feeds.php', {'action': 'add', 'name': 'r2', 'tag_filter': '', 'max_age_hours': '24', 'allowed_sources': '10.9.9.0/24'})[1]).group(1)}", {"X-Forwarded-Proto": "https"})
check(code == 403 and "not allowed from your address" in body, "token pinned to other sources is refused from here")
remote(saved_remote)

# ---------------------------------------------------------------- self-update
section("Self-update: code travels inside the authenticated response")
p = SRV + "/agents/windows/ip-agent.ps1"; s = open(p).read(); open(p, "w").write(s.replace("$AGENT_VERSION = '2.0.0'", "$AGENT_VERSION = '2.0.1'"))
rc, out = run_win()
check(rc == 10 and "updated to 2.0.1" in out, "Windows agent installed the update and exited 10 for restart", out[-300:])
check("'2.0.1'" in open(WIN + "/ip-agent.ps1").read() and open(WIN + "/ip-agent.ps1").read() == open(p).read(), "installed file is byte-identical to the server's")
rc, out = run_win()
check(rc == 0 and agent(WIN_ID)["agent_version"] == "2.0.1", "restarted agent reports 2.0.1 and gets no further update offer")
p = SRV + "/agents/docker/agent.php"; s = open(p).read(); open(p, "w").write(s.replace("const AGENT_VERSION = '2.0.0';", "const AGENT_VERSION = '2.0.1';"))
dock_cycle(15); time.sleep(10)
check(agent(DOCK_ID)["agent_version"] == "2.0.1", "Docker agent self-updated into its volume and reports 2.0.1",
      subprocess.run(["docker", "logs", "--tail", "6", "ipfailover-agent"], capture_output=True, text=True).stdout)

# ---------------------------------------------------------------- server key rotation
section("Server key rotation: agents re-pin automatically")
oldk = json.load(open(WDATA + "/state.json"))["server_key_id"]
b.get("settings.php"); b.post("settings.php", {"action": "rotate_server_key"})
rc, out = run_win()
newk = json.load(open(WDATA + "/state.json"))["server_key_id"]
check(newk != oldk and "server key rotated" in out, f"Windows agent re-pinned {oldk} -> {newk}")
rc, out = run_win()
check(rc == 0, "and keeps checking in on the new key")

# ---------------------------------------------------------------- roles, 2FA
section("Technician role and two-factor sign-in")
b.get("users.php"); b.post("users.php", {"action": "add", "username": "tech1", "name": "Tech One", "email": "t1@test.local", "role": "tech", "password": "tech-password-123"})
tb = Browser(); tb.get("login.php"); tb.post("login.php", {"username": "tech1", "password": "tech-password-123"})
c, t, h = tb.get("settings.php"); check(c == 403, "tech can't open Settings")
c, t, h = tb.get(f"agent.php?id={WIN_ID}")
check("Delete site" not in t and "Danger zone" not in t and "Rotate key" not in t, "admin-only controls are absent for a tech (not just disabled)")
check('href="settings.php"' not in t and 'href="users.php"' not in t, "admin nav entries absent for a tech")
c, t, h = tb.post("agent.php", {"id": WIN_ID, "action": "delete"}, follow=False)
check(c == 403 and agent(WIN_ID), "tech's hand-built delete POST is refused server-side")
c, t, h = tb.post("agent.php", {"id": WIN_ID, "action": "delete", "csrf": "forged"}, follow=False)
check(c == 400, "a POST without the session's CSRF token is refused")
c, t, h = tb.get("account.php"); c, t, h = tb.post("account.php", {"action": "totp_start"})
sec = re.search(r'id="totpkey">([^<]+)<', t).group(1)
c, t, h = tb.post("account.php", {"action": "totp_confirm", "code": totp(sec)})
check(("ok", "Two-factor sign-in is on.") in flashes(t), "tech enrolls TOTP with a real authenticator code")
tb2 = Browser(); tb2.get("login.php"); c, t, h = tb2.post("login.php", {"username": "tech1", "password": "tech-password-123"})
check("Authenticator code" in t and "Sign out" not in t, "password alone is not enough once 2FA is on")
c, t, h = tb2.post("login.php", {"code": "000000"})
check("didn" in t, "wrong code refused")
time.sleep(31)  # the enrollment code's step is spent; use the next one
c, t, h = tb2.post("login.php", {"code": totp(sec)})
check("Sign out" in t, "correct code completes sign-in")

# ---------------------------------------------------------------- decommission + cleanup
section("Decommission, stale cleanup, delete with record removal")
b.get(f"agent.php?id={WIN_ID}"); b.post("agent.php", {"id": WIN_ID, "action": "decommission"})
rc, out = run_win()
check(rc == 20 and not os.path.exists(WDATA + "/agent-key.json") and not os.path.exists(WDATA + "/master.key"), "Windows agent destroyed its identity and exited 20 (launcher stops)", out[-200:])
st = json.load(open(WDATA + "/public/status.json"))
check(st.get("decommissioned"), "tray status shows decommissioned (grey)")
b.get(f"agent.php?id={DOCK_ID}"); b.post("agent.php", {"id": DOCK_ID, "action": "decommission"})
dock_cycle(12); dock_cycle(8)   # the second restart is the case that used to report "not provisioned" 
rc, hmsg = dock_health()
check(rc == 1 and "decommissioned" in hmsg, f"Docker healthcheck says to remove the container: {hmsg}")
x("UPDATE agents SET decommissioned_at = ? WHERE decommission = 1", int(time.time()))
c, t, h = b.get("index.php?show=stale")
check("SmithDental-PBX" in t and "Other-site" in t, "decommissioned sites appear under Stale")
c, t, h = b.post("index.php", {"action": "delete_stale", "remove_records": "1"})
names = {r["name"] for r in mock()["cf"].values()}
check(not q("SELECT * FROM agents") and RHOST not in names and "smith-pbx.example.org." not in mock()["pdns"]["example.org."],
      "Delete all stale removed the sites AND their Cloudflare/PowerDNS records")
check(any("Agent deleted" in e["message"] for e in q("SELECT message FROM events")), "deletions are audited")

# ---------------------------------------------------------------- backup / restore
section("Encrypted backup and restore")
env = {**os.environ, "IPF_PASSPHRASE": "a-long-backup-passphrase"}
r = subprocess.run(["php", SRV + "/bin/manage.php", "backup", T + "/srv.ipfbak"], capture_output=True, text=True, env=env)
check(r.returncode == 0 and open(T + "/srv.ipfbak", "rb").read(8) == b"IPFBAK01", "backup written")
R2 = S + "/srv-restore"; shutil.rmtree(R2, True); shutil.copytree(SRV, R2, ignore=shutil.ignore_patterns("data"))
r = subprocess.run(["php", R2 + "/bin/manage.php", "restore", T + "/srv.ipfbak"], capture_output=True, text=True, env={**env, "IPF_PASSPHRASE": "wrong-passphrase-xx"})
check(r.returncode != 0 and "wrong passphrase" in r.stderr, "wrong passphrase refused")
r = subprocess.run(["php", R2 + "/bin/manage.php", "restore", T + "/srv.ipfbak"], capture_output=True, text=True, env=env)
s2 = subprocess.run(["php", "-r", f'require "{R2}/src/bootstrap.php"; echo decrypt_json(db_one("select * from dns_accounts where provider=?",["powerdns"])["config_enc"])["api_key"];'], capture_output=True, text=True)
check(r.returncode == 0 and s2.stdout.strip() == "pdns-key", "restored server decrypts its stored credentials")

subprocess.run(["docker", "rm", "-f", "ipfailover-agent"], capture_output=True)
print(f"\n{ok} passed, {bad} failed"); sys.exit(1 if bad else 0)
