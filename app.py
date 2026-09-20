#!/usr/bin/env python3
"""
Stripe Checker API — Flask wrapper
Deploy on Render → get URL → call from Telegram bot.
"""

import os
import json
import re
import time
from flask import Flask, request, jsonify
from stripe_checker import (
    process_card_enhanced,
    check_site_status,
    add_site,
    remove_site,
    get_all_sites,
    clear_all_sites,
)

app = Flask(__name__)


def normalize_card(raw: str):
    if not raw:
        return None
    m = re.search(
        r'(\d{15,16})[|\s/:\-]+(\d{1,2})[|\s/:\-]+(\d{2,4})[|\s/:\-]+(\d{3,4})',
        raw.strip()
    )
    if not m:
        return None
    cc, mm, yy, cvv = m.groups()
    mm = mm.zfill(2)
    if len(yy) == 4:
        yy = yy[2:]
    if not (13 <= len(cc) <= 19 and 1 <= int(mm) <= 12 and len(cvv) in (3, 4)):
        return None
    return f"{cc}|{mm}|{yy}|{cvv}"


def normalize_status(raw_status: str, raw_response: str):
    low = (raw_response or "").lower()
    s = (raw_status or "").lower()

    if "3d" in low or "authentication" in low or "otp" in low or "verify" in low:
        return "3DS", _clean_msg(raw_response)

    if s == "approved" or "succeeded" in low or "card added successfully" in low or \
       ("success" in low and "decline" not in low):
        return "APPROVED", _clean_msg(raw_response)

    if "charged" in low or "order placed" in low:
        return "CHARGED", _clean_msg(raw_response)

    if "decline" in low:
        return "DECLINED", _clean_msg(raw_response)

    if s == "declined":
        return "DECLINED", _clean_msg(raw_response)

    if s == "error" or "error" in low:
        return "ERROR", _clean_msg(raw_response)

    return ("APPROVED" if s == "approved" else "DECLINED"), _clean_msg(raw_response)


def _clean_msg(raw: str) -> str:
    if not raw:
        return "Unknown"
    raw = str(raw).strip()
    try:
        data = json.loads(raw)
        if isinstance(data, dict):
            err = data.get("error") or data.get("data", {}).get("error")
            if isinstance(err, dict) and err.get("message"):
                return err["message"]
            if isinstance(err, str):
                return err
            if data.get("message"):
                return data["message"]
            if data.get("response"):
                return data["response"]
    except Exception:
        pass
    if len(raw) > 200:
        raw = raw[:200] + "…"
    return raw


@app.route("/stripe", methods=["GET", "POST"])
def stripe_check():
    if request.method == "POST":
        payload = request.get_json(silent=True) or request.form.to_dict()
    else:
        payload = request.args.to_dict()

    raw_cc  = payload.get("cc") or payload.get("card") or ""
    site    = (payload.get("site") or "").strip()
    proxy   = (payload.get("proxy") or "").strip() or None
    chat_id = payload.get("chat_id") or None

    card = normalize_card(raw_cc)
    if not card:
        return jsonify({
            "status": "ERROR",
            "response": "Invalid card format. Use CC|MM|YY|CVV",
            "cc": raw_cc, "gateway": "Stripe Auth", "price": "$0"
        }), 400

    if not site:
        all_sites = get_all_sites()
        if not all_sites:
            return jsonify({
                "status": "ERROR",
                "response": "No sites configured. Add one via /addsite",
                "cc": card, "gateway": "Stripe Auth", "price": "$0"
            }), 400
        site = all_sites[0]

    site = site.replace("https://", "").replace("http://", "").rstrip("/")

    # If no proxy given, try global proxies.txt on the API server
    if not proxy:
        try:
            pf = os.path.join(os.path.dirname(os.path.abspath(__file__)), "proxies.txt")
            if os.path.exists(pf):
                with open(pf) as f:
                    lines = [l.strip() for l in f if l.strip() and not l.startswith("#")]
                if lines:
                    import random as _r
                    proxy = _r.choice(lines)
        except Exception:
            pass

    start = time.time()
    try:
        result = process_card_enhanced(
            domain=site,
            ccx=card,
            chat_id=chat_id,
            use_registration=True,
            received_proxy=proxy      # can be None — checker now handles that
        )
    except Exception as e:
        return jsonify({
            "status": "ERROR",
            "response": f"Checker crash: {str(e)[:120]}",
            "cc": card, "site": site, "gateway": "Stripe Auth",
            "price": "$0", "time": round(time.time() - start, 2)
        }), 500

    elapsed = round(time.time() - start, 2)
    final_status, clean_response = normalize_status(
        result.get("status", "ERROR"),
        result.get("response", "Unknown")
    )

    return jsonify({
        "status":   final_status,
        "response": clean_response,
        "cc":       card,
        "site":     site,
        "gateway":  "Stripe Auth",
        "price":    "$0",
        "time":     elapsed,
    })


@app.route("/sites", methods=["GET"])
def list_sites():
    return jsonify({"sites": get_all_sites(), "count": len(get_all_sites())})


@app.route("/addsite", methods=["POST", "GET"])
def api_add_site():
    data = request.get_json(silent=True) or request.args.to_dict()
    site = (data.get("site") or "").strip()
    if not site:
        return jsonify({"ok": False, "error": "Missing site"}), 400
    ok = add_site(site)
    return jsonify({"ok": ok, "sites": get_all_sites()})


@app.route("/removesite", methods=["POST", "GET"])
def api_remove_site():
    data = request.get_json(silent=True) or request.args.to_dict()
    site = (data.get("site") or "").strip()
    if not site:
        return jsonify({"ok": False, "error": "Missing site"}), 400
    ok = remove_site(site)
    return jsonify({"ok": ok, "sites": get_all_sites()})


@app.route("/clearsites", methods=["POST"])
def api_clear_sites():
    clear_all_sites()
    return jsonify({"ok": True, "sites": []})


@app.route("/sitecheck", methods=["GET", "POST"])
def api_site_check():
    data = request.get_json(silent=True) or request.args.to_dict()
    site = (data.get("site") or "").strip()
    proxy = (data.get("proxy") or "").strip() or None
    chat_id = data.get("chat_id")
    if not site:
        return jsonify({"ok": False, "error": "Missing site"}), 400
    result = check_site_status(site, chat_id=chat_id, received_proxy=proxy)
    return jsonify(result)


@app.route("/health", methods=["GET"])
def health():
    return jsonify({
        "ok": True,
        "sites": len(get_all_sites()),
        "time": time.strftime("%Y-%m-%d %H:%M:%S")
    })


@app.route("/", methods=["GET"])
def root():
    return jsonify({
        "name": "Stripe Checker API",
        "endpoints": {
            "check":  "/stripe?cc=CC|MM|YY|CVV&site=example.com&proxy=ip:port:user:pass",
            "sites":  "/sites",
            "add":    "POST /addsite {site}",
            "remove": "POST /removesite {site}",
            "health": "/health",
        }
    })


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, threaded=True)
