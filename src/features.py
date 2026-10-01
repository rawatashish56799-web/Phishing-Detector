import re, tldextract
from email.utils import parseaddr
from urllib.parse import urlparse

_ext = tldextract.TLDExtract(suffix_list_urls=())  # offline, no network needed

URGENT = ["verify", "urgent", "suspended", "immediately", "confirm",
          "password", "click here", "limited time", "act now", "locked"]
RISKY_EXT = (".exe", ".scr", ".js", ".vbs", ".iso", ".html", ".htm",
             ".docm", ".xlsm", ".zip", ".bat")
IP_RE = re.compile(r'^\d{1,3}(\.\d{1,3}){3}$')

def _domain(host):
    host = host.strip().lower()
    d = _ext(host)
    if d.suffix:
        return f"{d.domain}.{d.suffix}"
    parts = host.split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else host

def _addr_domain(header):
    addr = parseaddr(header)[1]
    return _domain(addr.split("@")[-1]) if "@" in addr else ""

def extract_features(p):
    h, text, urls = p["headers"], p["text"].lower(), p["urls"]
    from_dom = _addr_domain(h["from"])
    reply_dom = _addr_domain(h["reply_to"])
    ret_dom = _addr_domain(h["return_path"])

    hosts = [urlparse(u).netloc.split("@")[-1].split(":")[0] for u in urls]

    link_mismatch = 0
    for label, href in p["links"]:
        shown = re.sub(r'^https?://', '', label.strip()).split("/")[0]
        if re.search(r'\w+\.\w{2,}', shown):
            if _domain(shown) != _domain(urlparse(href).netloc.split(":")[0]):
                link_mismatch = 1

    return {
        "reply_mismatch": int(bool(reply_dom) and reply_dom != from_dom),
        "return_path_mismatch": int(bool(ret_dom) and ret_dom != from_dom),
        "num_urls": len(urls),
        "ip_in_url": int(any(IP_RE.match(x) for x in hosts)),
        "at_in_url": int(any("@" in u for u in urls)),
        "no_https": int(any(u.startswith("http://") for u in urls)),
        "long_url": int(any(len(u) > 75 for u in urls)),
        "many_subdomains": int(any(x.count(".") >= 3 and not IP_RE.match(x) for x in hosts)),
        "link_text_mismatch": link_mismatch,
        "urgent_words": sum(w in text for w in URGENT),
        "num_attachments": len(p["attachments"]),
        "risky_attachment": int(any(a.lower().endswith(RISKY_EXT) for a in p["attachments"])),
    }
