import os
import traceback
import logging
from logging.handlers import RotatingFileHandler

import joblib
import pandas as pd
from flask import Flask, request, jsonify, render_template

from features import extract_features
from train import train_and_save_model
from imap_utils import fetch_recent_emails
from parsers import parse_uploaded_file
from security import require_rate_limit, apply_security_headers, require_admin_key

MODEL_PATH = "models/hamisecure_model.pkl"
DATASET_PATH = "data/dataset.csv"
ALLOWLIST_PATH = "config/allowlist_domains.txt"

DEFAULT_THRESHOLD = float(os.getenv("HAMISECURE_THRESHOLD", "0.90"))

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 10 * 1024 * 1024  # 10MB uploads

model = None
FEATURE_COLS = None
ALLOWLIST = set()

# ---------- Logging ----------
os.makedirs("logs", exist_ok=True)
handler = RotatingFileHandler("logs/app.log", maxBytes=500_000, backupCount=3)
handler.setLevel(logging.INFO)
formatter = logging.Formatter("[%(asctime)s] %(levelname)s - %(message)s")
handler.setFormatter(formatter)
app.logger.addHandler(handler)
app.logger.setLevel(logging.INFO)


@app.after_request
def _sec_headers(resp):
    return apply_security_headers(resp)


def load_allowlist():
    if not os.path.exists(ALLOWLIST_PATH):
        return set()
    out = set()
    with open(ALLOWLIST_PATH, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip().lower()
            if not line or line.startswith("#"):
                continue
            out.add(line)
    return out


def load_or_train():
    global model, FEATURE_COLS, ALLOWLIST
    ALLOWLIST = load_allowlist()

    if not os.path.exists(MODEL_PATH):
        app.logger.info("Model not found, training...")
        train_and_save_model(dataset=DATASET_PATH, model_path=MODEL_PATH)

    obj = joblib.load(MODEL_PATH)
    model = obj["model"]
    FEATURE_COLS = obj["feature_cols"]
    app.logger.info("Model loaded.")


def engineered_subset(feats: dict) -> dict:
    return {k: feats.get(k, 0) for k in FEATURE_COLS}


def allowlist_override(sender_domain: str):
    d = (sender_domain or "").lower().strip()
    if d and d in ALLOWLIST:
        return True, f"Allowlist override: {d}"
    return False, ""


def safe_override(feats: dict):
    """
    Conservative safe override to reduce false positives:
    If NO sensitive info and NO urgency, consider legit when:
    - unsubscribe exists OR
    - low link count OR
    - subject resembles transaction/notification
    """
    no_sensitive = int(feats.get("requests_sensitive_info", 0)) == 0
    no_urgency = int(feats.get("has_urgency_language", 0)) == 0

    links_count_log = float(feats.get("links_count_log", 0.0))
    low_links = links_count_log <= 1.10  # ~ 0-2 links
    has_unsub = int(feats.get("has_unsubscribe", 0)) == 1

    subj = (feats.get("subject") or "").lower()
    transaction_like = any(x in subj for x in [
        "transaction", "fund transfer", "bank load", "payment", "receipt",
        "notification", "statement", "alert"
    ])

    if no_sensitive and no_urgency and (has_unsub or low_links or transaction_like):
        return True, "Safe override: no sensitive/urgency; newsletter/low-link/transaction pattern."
    return False, ""


def readable_report(feats: dict, prob: float, pred: str, override_reason: str, headers: dict | None):
    """
    Create a human-readable report sections for the frontend.
    """
    risks = []
    positives = []

    if feats.get("requests_sensitive_info", 0):
        risks.append("Requests sensitive info (OTP/password/PIN/card details).")
    else:
        positives.append("No sensitive information request detected.")

    if feats.get("has_urgency_language", 0):
        risks.append("Urgency/pressure wording detected.")
    else:
        positives.append("No urgency/pressure wording detected.")

    if feats.get("has_phish_action", 0):
        risks.append("Contains action prompts (login/verify/reset/update).")
    else:
        positives.append("No strong action prompt pattern detected.")

    if feats.get("has_url_shortener", 0):
        risks.append("URL shortener detected (can hide destination).")
    if feats.get("has_ip_url", 0):
        risks.append("IP-based URL detected (high risk).")
    if feats.get("has_insecure_http", 0):
        risks.append("Uses insecure HTTP links.")
    if feats.get("has_long_url", 0):
        risks.append("Very long URL detected (may include tracking/obfuscation).")

    if feats.get("digit_count", 0) > 0:
        risks.append("Digits in sender domain (can indicate spoofing).")
    if feats.get("hyphen_count", 0) > 0:
        risks.append("Hyphenated sender domain (common in lookalike domains).")

    links = float(feats.get("links_count_log", 0.0))
    if links > 1.10:
        risks.append("Multiple links present (review destination domains).")
    else:
        positives.append("Low link count.")

    # Header hints (if provided from .eml/imap)
    header_notes = []
    if headers:
        ar = headers.get("Authentication-Results", "") or headers.get("authentication-results", "")
        if ar:
            header_notes.append("Authentication-Results header is present (SPF/DKIM/DMARC info may exist).")
        reply_to = headers.get("Reply-To", "") or headers.get("reply-to", "")
        from_ = headers.get("From", "") or headers.get("from", "")
        if reply_to and from_ and reply_to != from_:
            header_notes.append("Reply-To differs from From (potential impersonation technique).")

    return {
        "summary": {
            "prediction": pred,
            "probability": prob,
            "threshold": DEFAULT_THRESHOLD,
            "override_reason": override_reason or "No override applied."
        },
        "risk_indicators": risks[:10] if risks else ["No strong phishing indicators detected."],
        "legit_indicators": positives[:10] if positives else [],
        "header_notes": header_notes[:6],
        "feature_values": engineered_subset(feats),
    }


def score_email(subject: str, body: str, sender_email: str, headers=None):
    feats = extract_features({"subject": subject, "body": body, "sender_email": sender_email})

    ok, why = allowlist_override(feats.get("sender_domain", ""))
    if ok:
        return {
            "prediction": "legit",
            "probability": 0.10,
            "engineered_features": engineered_subset(feats),
            "override": {"applied": True, "reason": why},
            "report": readable_report(feats, 0.10, "legit", why, headers),
        }

    X = pd.DataFrame([engineered_subset(feats)])
    prob = float(model.predict_proba(X)[0][1])

    overridden, reason = safe_override(feats)
    if overridden:
        pred = "legit"
        prob = min(prob, 0.60)
    else:
        pred = "fraud" if prob >= DEFAULT_THRESHOLD else "legit"

    return {
        "prediction": pred,
        "probability": prob,
        "engineered_features": engineered_subset(feats),
        "override": {"applied": overridden, "reason": reason or "No override applied."},
        "report": readable_report(feats, prob, pred, reason, headers),
    }


@app.route("/")
def home():
    rl = require_rate_limit()
    if rl:
        return rl
    return render_template("index.html")


@app.route("/predict", methods=["POST"])
def predict():
    rl = require_rate_limit()
    if rl:
        return rl

    try:
        data = request.get_json(force=True) or {}
        subject = data.get("subject", "") or ""
        body = data.get("body", "") or ""
        sender_email = data.get("sender_email", "") or ""

        out = score_email(subject, body, sender_email, headers=None)
        out["threshold"] = DEFAULT_THRESHOLD
        return jsonify(out)

    except Exception as e:
        app.logger.error("Predict error: %s", e)
        return jsonify({"error": "Internal error while analyzing email."}), 500


@app.route("/upload/analyze", methods=["POST"])
def upload_analyze():
    rl = require_rate_limit()
    if rl:
        return rl

    try:
        if "file" not in request.files:
            return jsonify({"error": "No file uploaded."}), 400

        info = parse_uploaded_file(request.files["file"])
        out = score_email(info["subject"], info["body"], info["sender_email"], headers=info.get("headers"))
        out["parsed"] = {
            "subject": info["subject"],
            "sender_email": info["sender_email"],
            "body_preview": (info["body"][:300] if info["body"] else "")
        }
        return jsonify(out)

    except Exception as e:
        app.logger.error("Upload analyze error: %s", e)
        return jsonify({"error": "Failed to parse/analyze the file."}), 500


@app.route("/imap/scan_ui", methods=["POST"])
def imap_scan_ui():
    rl = require_rate_limit()
    if rl:
        return rl

    try:
        data = request.get_json(force=True) or {}

        host = (data.get("imap_host") or "").strip()
        user = (data.get("imap_user") or "").strip()
        password = data.get("imap_password") or ""
        folder = (data.get("imap_folder") or "INBOX").strip()

        port = int(data.get("imap_port") or 993)
        use_ssl = bool(data.get("imap_ssl", True))
        limit = int(data.get("limit") or 10)

        if not host or not user or not password:
            return jsonify({"error": "Missing IMAP host/username/password."}), 400

        emails = fetch_recent_emails(host, port, use_ssl, user, password, folder, limit)

        results = []
        for em in emails:
            out = score_email(em.get("subject",""), em.get("body",""), em.get("from",""), headers=em.get("headers"))
            results.append({
                "from": em.get("from",""),
                "subject": em.get("subject",""),
                "snippet": (em.get("body","")[:240] if em.get("body") else ""),
                **out
            })

        return jsonify({"count": len(results), "results": results})

    except Exception as e:
        app.logger.error("IMAP error: %s", e)
        return jsonify({"error": "IMAP scan failed. Check host/port/SSL/App password."}), 400


@app.route("/retrain", methods=["POST"])
def retrain():
    rl = require_rate_limit()
    if rl:
        return rl

    auth = require_admin_key()
    if auth:
        return auth

    try:
        train_and_save_model(dataset=DATASET_PATH, model_path=MODEL_PATH)
        load_or_train()
        return jsonify({"status": "ok"})
    except Exception as e:
        app.logger.error("Retrain error: %s", e)
        return jsonify({"error": "Retraining failed."}), 500


load_or_train()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)

