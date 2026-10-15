"""Tiny browser: cookie jar + CSRF scraping. Import from tests."""
import re, urllib.request, urllib.parse, http.cookiejar, os
BASE = os.environ["IPF_TEST_BASE"]
class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k): return None
class Browser:
    def __init__(s, base=BASE):
        s.base = base; s.jar = http.cookiejar.CookieJar()
        s.op = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(s.jar), NoRedirect)
        s.csrf = None
    def req(s, method, path, data=None, follow=True):
        body = urllib.parse.urlencode(data, doseq=True).encode() if data is not None else None
        r = urllib.request.Request(s.base + "/" + path.lstrip("/"), data=body, method=method)
        try:
            resp = s.op.open(r); code = resp.status; text = resp.read().decode("utf-8", "replace"); hdr = resp.headers
        except urllib.error.HTTPError as e:
            code = e.code; text = e.read().decode("utf-8", "replace"); hdr = e.headers
        if code in (301, 302, 303) and follow:
            loc = hdr["Location"]
            return s.req("GET", loc if not loc.startswith("http") else urllib.parse.urlparse(loc).path + ("?" + urllib.parse.urlparse(loc).query if urllib.parse.urlparse(loc).query else ""))
        m = re.search(r'name="csrf" value="([^"]+)"', text)
        if m: s.csrf = m.group(1)
        return code, text, hdr
    def get(s, path): return s.req("GET", path)
    def post(s, path, data, follow=True):
        d = dict(data); d.setdefault("csrf", s.csrf); return s.req("POST", path, d, follow)
def flashes(html):
    import html as H
    return [(k, H.unescape(m)) for k, m in re.findall(r"<div class=\"flash (\w+)\">(.*?)</div>", html)]
