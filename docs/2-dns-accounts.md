# 2. Add a DNS account (once per provider)

A DNS account is one provider login. You set it up once; technicians just pick
it from a list. The password/token is stored encrypted and **never** goes to a site.

## Steps

1. Sign in as an admin → **DNS accounts**.
2. Pick the **Provider**, give it a **Name** (e.g. "DP Solutions Cloudflare").
3. Fill in the credential (see below).
4. **Domain for random names** (Cloudflare and PowerDNS only): the zone sites
   get names under, e.g. `dyn.yourdomain.com`. Leave it blank if you'd rather
   type every name.
5. **Save**, then click **Test**.

## What to put in

| Provider | What you need |
|---|---|
| **Cloudflare** | An API token: Cloudflare → My Profile → API Tokens → Create Token → "Edit zone DNS" → limit it to your zone. Zone ID is optional. |
| **PowerDNS** | API URL (e.g. `http://10.20.0.53:8081`) and API key. In `pdns.conf`: `api=yes`, `api-key=...`, `webserver=yes`, `webserver-address=0.0.0.0`, `webserver-allow-from=<this server's IP>`. Tick NOTIFY if you have secondaries. |
| **No-IP / Dynu / Dyn / ChangeIP / OVH** | Pick it under **Service**, then username + password (or update key). The hostname must already exist in that account. |
| **Custom DynDNS** | An update URL with `{hostname}` and `{ip}` in it, plus username/password if it uses them. |
| **DuckDNS** | Your account token. Make the subdomain on duckdns.org first. |
| **FreeDNS (afraid.org)** | Nothing here — each name's own update token is entered when you add the name. |
| **None** | Nothing. Use this when you only want the IP tracked (alerts + allowlist feeds). |

## Which one is best?

**Cloudflare or PowerDNS.** One credential covers every name, it can create new
names (so random names work), and the server can read the record back to catch
anyone changing it by hand.

Next: [3. Add a site](3-add-a-site.md)
