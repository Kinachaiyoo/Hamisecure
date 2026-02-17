import os
import email
from email.header import decode_header
import re

HTML_TAG_RE = re.compile(r"<[^>]+>")


def _decode_mime(s):
    if not s:
        return ""
    parts = decode_header(s)
    out = []
    for t, enc in parts:
        if isinstance(t, bytes):
            out.append(t.decode(enc or "utf-8", errors="replace"))
        else:
            out.append(t)
    return "".join(out)


def strip_html(html_text: str) -> str:
    if not html_text:
        return ""
    text = HTML_TAG_RE.sub(" ", html_text)
    text = re.sub(r"\s+", " ", text).strip()
    return text


def extract_body_from_message(msg: email.message.Message) -> str:
    text_plain = []
    text_html = []

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
        return strip_html("\n".join(text_html))
    return ""


def parse_uploaded_file(file_storage):
    """
    Returns dict {subject, sender_email, body, headers}
    """
    filename = (file_storage.filename or "").lower()
    raw = file_storage.read()

    # .eml
    if filename.endswith(".eml"):
        msg = email.message_from_bytes(raw)
        subject = _decode_mime(msg.get("Subject", ""))
        from_ = _decode_mime(msg.get("From", ""))
        body = extract_body_from_message(msg)

        headers = {}
        for k, v in msg.items():
            headers[k] = _decode_mime(v)

        return {
            "subject": subject,
            "sender_email": from_,
            "body": body,
            "headers": headers
        }

    # .html
    if filename.endswith(".html") or filename.endswith(".htm"):
        text = raw.decode("utf-8", errors="replace")
        return {"subject": "", "sender_email": "", "body": strip_html(text), "headers": {}}

    # .txt or anything else
    text = raw.decode("utf-8", errors="replace")
    return {"subject": "", "sender_email": "", "body": text, "headers": {}}

