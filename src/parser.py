import email, re
from email import policy
from bs4 import BeautifulSoup

URL_RE = re.compile(r'https?://[^\s"\'<>]+')

def parse_eml(path):
    with open(path, "rb") as f:
        msg = email.message_from_binary_file(f, policy=policy.default)

    headers = {
        "from": str(msg["From"] or ""),
        "reply_to": str(msg["Reply-To"] or ""),
        "return_path": str(msg["Return-Path"] or ""),
        "subject": str(msg["Subject"] or ""),
        "auth_results": str(msg["Authentication-Results"] or ""),
    }

    body = msg.get_body(preferencelist=("html", "plain"))
    content = body.get_content() if body else ""

    links = []
    if "<a " in content.lower() or "<html" in content.lower():
        soup = BeautifulSoup(content, "lxml")
        for a in soup.find_all("a", href=True):
            links.append((a.get_text(" ", strip=True), a["href"]))
        text = soup.get_text(" ", strip=True)
    else:
        text = content

    urls = list(dict.fromkeys(
        URL_RE.findall(content) + [h for _, h in links if h.startswith("http")]
    ))
    attachments = [p.get_filename() for p in msg.iter_attachments() if p.get_filename()]

    return {"headers": headers, "text": text, "urls": urls,
            "links": links, "attachments": attachments}
