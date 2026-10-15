import sys, re, json, subprocess, os
BASE = os.environ["DYNALLOW_TEST_BASE"]
MOCK = os.environ["DYNALLOW_TEST_MOCK"]
SMTP_PORT = os.environ["DYNALLOW_TEST_SMTP_PORT"]
sys.path.insert(0, sys.argv[1]); from web import Browser, flashes
S = sys.argv[1]; ok = 0; bad = 0
def check(cond, msg):
    global ok, bad
    if cond: ok += 1; print("  PASS", msg)
    else: bad += 1; print("  FAIL", msg)

b = Browser()
c, t, h = b.get("index.php")
check("login.php" in t or "Sign in" in t, "anonymous user is sent to login")
c, t, h = b.get("login.php")
c, t, h = b.post("login.php", {"username": "admin", "password": "wrong-password"})
check("Wrong username or password" in t, "bad password refused")
c, t, h = b.post("login.php", {"username": "admin", "password": "correct-horse-battery"})
check("Sites" in t and "Sign out" in t, "admin logs in and sees dashboard")
check("cron job is not running" in t, "dead-cron banner shown")
check("plain HTTP" in t, "plain-HTTP warning shown")
check("Content-Security-Policy" in h and "script-src 'self'" in h["Content-Security-Policy"], "CSP header present, no unsafe-inline")
check(not re.search(r'\son[a-z]+="', t) and "<script>" not in t, "no inline handlers or inline scripts on dashboard")

# settings
c, t, h = b.get("settings.php")
c, t, h = b.post("settings.php", {"action": "save", "section": "General", "public_url": BASE, "timezone": "America/Chicago",
    "default_interval_sec": "60", "default_missed": "2", "ip_check_urls": MOCK + "/ip", "ip_confirm_checkins": "1"})
check(("ok", "General settings saved.") in flashes(t), "general settings saved")
c, t, h = b.post("settings.php", {"action": "save", "section": "General", "public_url": "not a url", "timezone": "America/Chicago",
    "default_interval_sec": "99999", "default_missed": "2", "ip_check_urls": MOCK + "/ip", "ip_confirm_checkins": "1"})
check(any("must start with http" in m for _, m in flashes(t)), "bad public URL rejected")
check('value="3600"' in t, "out-of-range interval clamped to bound (3600)")
c, t, h = b.post("settings.php", {"action": "smtp", "smtp_host": "127.0.0.1", "smtp_port": SMTP_PORT, "smtp_security": "none", "smtp_user": "", "smtp_pass": "", "smtp_from": "ipf@test.local", "smtp_from_name": "IPF"})
c, t, h = b.post("settings.php", {"action": "save", "section": "Alerts", "alert_emails": "noc@test.local", "notify_ip_change": "1", "dns_fail_alert_after": "2", "mismatch_alert_minutes": "1", "webhook_url": MOCK + "/hook", "cron_ping_url": ""})
c, t, h = b.post("settings.php", {"action": "test_mail"})
check(any("Test email sent" in m for _, m in flashes(t)), "test email sends via built-in SMTP")

# DNS accounts
c, t, h = b.get("accounts.php")
c, t, h = b.post("accounts.php", {"action": "save", "provider": "cloudflare", "name": "DP Cloudflare", "p[cloudflare][api_token]": "cf-good-token", "p[cloudflare][zone_id]": "", "domain": "example.com"})
check(("ok", "Saved.") in flashes(t), "Cloudflare account added")
check("cf-good-token" not in t, "Cloudflare token is never rendered back")
c, t, h = b.post("accounts.php", {"action": "save", "provider": "powerdns", "name": "Our PowerDNS", "p[powerdns][api_url]": MOCK + "/pdns", "p[powerdns][api_key]": "pdns-key", "p[powerdns][server_id]": "localhost", "p[powerdns][zone]": "", "p[powerdns][notify]": "1", "domain": "example.org"})
check(("ok", "Saved.") in flashes(t), "PowerDNS account added")
c, t, h = b.post("accounts.php", {"action": "save", "provider": "dyndns2", "name": "No-IP main", "p[dyndns2][preset]": "custom", "p[dyndns2][update_url]": MOCK + "/nic/update?hostname={hostname}&myip={ip}", "p[dyndns2][username]": "u", "p[dyndns2][password]": "p", "domain": ""})
ids = {n: i for n, i in re.findall(r'<tr><td><b>([^<]+)</b>.*?\?edit=(\d+)', t, re.S)}
check(len(ids) == 3, f"three accounts listed {ids}")
c, t, h = b.post("accounts.php", {"action": "test", "id": ids["Our PowerDNS"]})
check(any("Connected: PowerDNS" in m for _, m in flashes(t)), "PowerDNS Test button talks to the API")
c, t, h = b.post("accounts.php", {"action": "test", "id": ids["DP Cloudflare"]})
check(any("Token is valid" in m for _, m in flashes(t)), "Cloudflare Test button verifies token")
# edit keeps secret when blank
c, t, h = b.get(f"accounts.php?edit={ids['DP Cloudflare']}")
check("saved — leave blank to keep" in t, "edit form shows secret as saved, not its value")
c, t, h = b.post("accounts.php", {"action": "save", "id": ids["DP Cloudflare"], "provider": "cloudflare", "name": "DP Cloudflare", "p[cloudflare][api_token]": "", "p[cloudflare][zone_id]": "", "domain": "example.com"})
c, t, h = b.post("accounts.php", {"action": "test", "id": ids["DP Cloudflare"]})
check(any("Token is valid" in m for _, m in flashes(t)), "blank secret on edit kept the stored token")

# survey: validation
c, t, h = b.get("survey.php")
check("data-survey" in t and t.count('class="step"') == 6, "survey renders 6 steps")
c, t, h = b.post("survey.php", {"customer": "", "name": "", "platform": "windows", "isp": "starlink", "cgnat": "yes", "multiwan": "no", "interval_sec": "60", "missed_threshold": "2", "alert_emails": "bad@@x", "tags": "", "trust_mode": "agree"})
f = [m for _, m in flashes(t)]
check(any("Customer is required" in m for m in f) and any("Not a valid email" in m for m in f), "survey validates required fields and emails")
# survey: create Windows site with a random Cloudflare name + PowerDNS custom name
c, t, h = b.post("survey.php", {"customer": "Smith Dental", "name": "SmithDental-PBX", "site_address": "1 Main", "site_contact": "Jo 555", "platform": "windows",
    "purpose[]": ["pbx", "vpn"], "notes": "", "isp": "starlink", "cgnat": "yes", "multiwan": "no", "interval_sec": "60", "missed_threshold": "2",
    "alert_emails": "tech@test.local", "tags": "pbx, Starlink", "trust_mode": "agree",
    "targets[0][account_id]": ids["DP Cloudflare"], "targets[0][name_mode]": "random", "targets[0][hostname]": "", "targets[0][ttl]": "120",
    "targets[1][account_id]": ids["Our PowerDNS"], "targets[1][name_mode]": "custom", "targets[1][hostname]": "smith-pbx", "targets[1][ttl]": "60"})
check("Download Windows profile" in t, "survey creates site and offers native Windows profile")
aid = re.search(r'name="id" value="(\d+)"', t).group(1)
host_random = re.search(r'<b class="mono">([a-z0-9]{12}\.example\.com)</b>', t)
check(host_random is not None, f"random Cloudflare name generated ({host_random.group(1) if host_random else None})")
check("smith-pbx.example.org" in t, "bare label placed under the PowerDNS account's domain")
check("Waiting for install" in t or "No profile issued" in t, "new site shows a NEUTRAL state, not an error")
check('badge bad' not in t.split('<h1>')[1].split('</h1>')[0], "no red badge on a freshly created site")
# duplicate hostname refused
c, t, h = b.post("survey.php", {"customer": "Other", "name": "Other-site", "platform": "docker", "isp": "cable", "cgnat": "no", "multiwan": "yes", "interval_sec": "60", "missed_threshold": "2",
    "alert_emails": "", "tags": "", "trust_mode": "agree", "targets[0][account_id]": ids["Our PowerDNS"], "targets[0][name_mode]": "custom", "targets[0][hostname]": "smith-pbx.example.org", "targets[0][ttl]": "60"})
check(any("already kept updated by" in m for _, m in flashes(t)), "a hostname can't be claimed by two sites")
c, t, h = b.post("survey.php", {"customer": "Other", "name": "Other-site", "platform": "docker", "isp": "cable", "cgnat": "no", "multiwan": "yes", "interval_sec": "60", "missed_threshold": "2",
    "alert_emails": "", "tags": "lxc", "trust_mode": "agree", "targets[0][account_id]": ids["No-IP main"], "targets[0][name_mode]": "random", "targets[0][hostname]": "", "targets[0][ttl]": "60"})
check(any("can't create new names" in m for _, m in flashes(t)), "random names refused for update-only providers")
c, t, h = b.post("survey.php", {"customer": "Other", "name": "Other-site", "platform": "docker", "isp": "cable", "cgnat": "no", "multiwan": "yes", "interval_sec": "60", "missed_threshold": "2",
    "alert_emails": "", "tags": "lxc", "trust_mode": "server", "targets[0][account_id]": ids["No-IP main"], "targets[0][name_mode]": "custom", "targets[0][hostname]": "other.ddns.net", "targets[0][ttl]": "60"})
check("Download Docker installer" in t, "Docker site created")
did = re.search(r'name="id" value="(\d+)"', t).group(1)

json.dump({"win": aid, "docker": did, "random_host": host_random.group(1) if host_random else None, "accounts": ids}, open(S + "/ids.json", "w"))
print(f"\n{ok} passed, {bad} failed"); sys.exit(1 if bad else 0)
