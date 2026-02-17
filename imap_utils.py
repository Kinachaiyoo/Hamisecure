import imaplib
import email
from email.header import decode_header
import re

HTML_TAG_RE = re.compile(r"<[^>]+>")


def _decode_mime_words(s):
    if not s:
        return ""
    parts = decode_header(s)
    out = []
    for text, enc in parts:
        if isinstance(text, bytes):
            out.append(text.decode(enc or "utf-8", errors="replace"))
        else:
            out.append(text)
    return "".join(out)


def _strip_html(html_text: str) -> str:
    if not html_text:
        return ""
    text = HTML_TAG_RE.sub(" ", html_text)
    text = re.sub(r"\s+", " ", text).strip()
    return text


def _extract_best_body(msg: email.message.Message) -> str:
    text_plain, text_html = [], []

    if msg.is_multipart():
        for part in msg.walk():
            ctype = (part.get_content_type() or "").lower()
            disp = (part.get("Content-Disposition") or "").lower()
            if "attachment" in disp:
                continue

            payload = part.get_payload(decode=True)
            if not payload:
                continue

            charset = part.get_content_charset() or "utf-8"
            content = payload.decode(charset, errors="replace")

            if ctype == "text/plain":
                text_plain.append(content)
            elif ctype == "text/html":
                text_html.append(content)
    else:
        payload = msg.get_payload(decode=True)
        if payload:
            charset = msg.get_content_charset() or "utf-8"
            content = payload.decode(charset, errors="replace")
            ctype = (msg.get_content_type() or "").lower()
            if ctype == "text/plain":
                text_plain.append(content)
            elif ctype == "text/html":
                text_html.append(content)

    if text_plain:
        return "\n".join(text_plain).strip()
    if text_html:
        return _strip_html("\n".join(text_html))
    return ""


def fetch_recent_emails(host: str, port: int, use_ssl: bool,
                        username: str, password: str,
                        folder: str = "INBOX", limit: int = 10):
    mail = imaplib.IMAP4_SSL(host, port) if use_ssl else imaplib.IMAP4(host, port)
    mail.login(username, password)
    mail.select(folder)

    typ, data = mail.search(None, "ALL")
    if typ != "OK":
        mail.logout()
        return []

    ids = data[0].split()
    ids = ids[-limit:] if limit > 0 else ids

    results = []
    for eid in reversed(ids):
        typ, msg_data = mail.fetch(eid, "(RFC822)")
        if typ != "OK":
            continue

        raw = msg_data[0][1]
        msg = email.message_from_bytes(raw)

        from_ = _decode_mime_words(msg.get("From", ""))
        subject = _decode_mime_words(msg.get("Subject", ""))
        body = _extract_best_body(msg)

        headers = {}
        for k, v in msg.items():
            headers[k] = _decode_mime_words(v)

        results.append({"from": from_, "subject": subject, "body": body, "headers": headers})

    mail.logout()
    return results

