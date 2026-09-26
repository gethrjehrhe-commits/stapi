#!/usr/bin/env python3
"""
Stripe Checker API — app.py
============================
Works with stripe_checker.py in the SAME directory (flat Replit layout):
 
  /home/runner/<project>/
    app.py                   ← this file
    stripe_checker.py        ← checker
    sites_config.json        ← auto-created
    working_gates.txt        ← auto-created
    proxies.txt              ← optional, one proxy per line
    user_proxies.json        ← auto-created by bot
 
Endpoints:
  GET  /stripe?cc=CC|MM|YY|CVV&site=example.com[&proxy=ip:port:user:pass]
  POST /stripe   {cc, site, proxy, chat_id}
  GET  /sites
  POST /addsite  {site}
  POST /removesite {site}
  POST /clearsites
  GET  /sitecheck?site=example.com[&proxy=...]
  POST /sitecheck {site, proxy}
  GET  /health
"""
 
import os
import json
import re
import time
import random
import logging
from flask import Flask, request, jsonify
 
# ── stripe_checker must be in the same directory as app.py ────────────────────
from stripe_checker import (
    process_card_enhanced,
    check_site_status,
    check_sites_from_file,
    add_site,
    remove_site,
    get_all_sites,
    clear_all_sites,
    get_next_site,
)
 
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    datefmt='%H:%M:%S'
)
log = logging.getLogger(__name__)
 
app = Flask(__name__)
 
_HERE = os.path.dirname(os.path.abspath(__file__))
 
 
# ── Helpers ───────────────────────────────────────────────────────────────────
 
def _load_proxy_from_file() -> str | None:
    """Read a random proxy from proxies.txt sitting next to app.py."""
    try:
        pf = os.path.join(_HERE, "proxies.txt")
        if os.path.exists(pf):
            with open(pf) as f:
                lines = [l.strip() for l in f
                         if l.strip() and not l.startswith("#")]
            if lines:
                return random.choice(lines)
    except Exception:
        pass
    return None
 
 
def normalize_card(raw: str) -> str | None:
    """
    Accept any common card format and return CC|MM|YY|CVV.
    Handles 2- and 4-digit years, spaces, pipes, dashes, slashes.
    """
    if not raw:
        return None
    m = re.search(
        r'(\d{13,19})[|\s/:\-]+(\d{1,2})[|\s/:\-]+(\d{2,4})[|\s/:\-]+(\d{3,4})',
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
 
 
def _classify(raw_status: str, raw_response: str) -> tuple[str, str]:
    """Map checker status + raw response → (FINAL_STATUS, clean_message)."""
    low = (raw_response or "").lower()
    s   = (raw_status  or "").lower()
 
    if any(x in low for x in ("3d", "authentication required", "otp", "verify your")):
        return "3DS", _clean_msg(raw_response)
    if s == "approved" or any(x in low for x in ("succeeded", "card added successfully")):
        return "APPROVED", _clean_msg(raw_response)
    if "success" in low and "decline" not in low:
        return "APPROVED", _clean_msg(raw_response)
    if any(x in low for x in ("charged", "order placed")):
        return "CHARGED", _clean_msg(raw_response)
    if "decline" in low or s == "declined":
        return "DECLINED", _clean_msg(raw_response)
    if s == "error" or "error" in low:
        return "ERROR", _clean_msg(raw_response)
    return ("APPROVED" if s == "approved" else "DECLINED"), _clean_msg(raw_response)
 
 
def _clean_msg(raw: str) -> str:
    """Extract the most useful human-readable string from any response shape."""
    if not raw:
        return "Unknown"
    raw = str(raw).strip()
    try:
        data = json.loads(raw)
        if isinstance(data, dict):
            # nested WooCommerce error shape
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
    return raw[:200] + ("…" if len(raw) > 200 else "")
 
 
def _error(msg: str, cc: str = "", site: str = "", code: int = 400):
    return jsonify({
        "status":   "ERROR",
        "response": msg,
        "cc":       cc,
        "site":     site,
        "gateway":  "Stripe Auth",
        "price":    "$0",
    }), code
 
 
# ── Routes ────────────────────────────────────────────────────────────────────
 
@app.route("/stripe", methods=["GET", "POST"])
def stripe_check():
    if request.method == "POST":
        payload = request.get_json(silent=True) or request.form.to_dict()
    else:
        payload = request.args.to_dict()
 
    raw_cc  = (payload.get("cc") or payload.get("card") or "").strip()
    site    = (payload.get("site") or "").strip()
    proxy   = (payload.get("proxy") or "").strip() or None
    chat_id = payload.get("chat_id") or None
 
    # ── Validate card ─────────────────────────────────────────────────────────
    card = normalize_card(raw_cc)
    if not card:
        return _error("Invalid card format. Use: CC|MM|YY|CVV", cc=raw_cc)
 
    # ── Resolve site ──────────────────────────────────────────────────────────
    if not site:
        all_sites = get_all_sites()
        if not all_sites:
            return _error("No sites configured. Add one via POST /addsite", cc=card)
        site = get_next_site()          # round-robin across all configured sites
 
    site = site.replace("https://", "").replace("http://", "").rstrip("/")
 
    # ── Resolve proxy ─────────────────────────────────────────────────────────
    # Priority: request param > proxies.txt > None (go direct)
    if not proxy:
        proxy = _load_proxy_from_file()
 
    # ── Run checker ───────────────────────────────────────────────────────────
    start = time.time()
    try:
        result = process_card_enhanced(
            domain=site,
            ccx=card,
            chat_id=chat_id,
            use_registration=True,
            received_proxy=proxy,
        )
    except Exception as e:
        log.exception("Checker crash")
        return _error(f"Checker crash: {str(e)[:150]}", cc=card, site=site, code=500)
 
    elapsed = round(time.time() - start, 2)
    final_status, clean_response = _classify(
        result.get("status",   "ERROR"),
        result.get("response", "Unknown"),
    )
 
    log.info(f"{card[:6]}xxxx | {site} | {final_status} | {clean_response[:60]} | {elapsed}s")
 
    return jsonify({
        "status":   final_status,
        "response": clean_response,
        "cc":       card,
        "site":     site,
        "gateway":  "Stripe Auth",
        "price":    "$0",
        "time":     elapsed,
    })
 
 
# ── Site management ───────────────────────────────────────────────────────────
 
@app.route("/sites", methods=["GET"])
def list_sites():
    sites = get_all_sites()
    return jsonify({"sites": sites, "count": len(sites)})
 
 
@app.route("/addsite", methods=["GET", "POST"])
def api_add_site():
    data = request.get_json(silent=True) or request.args.to_dict()
    site = (data.get("site") or "").strip()
    if not site:
        return jsonify({"ok": False, "error": "Missing ?site="}), 400
    ok = add_site(site)
    return jsonify({"ok": ok, "sites": get_all_sites()})
 
 
@app.route("/removesite", methods=["GET", "POST"])
def api_remove_site():
    data = request.get_json(silent=True) or request.args.to_dict()
    site = (data.get("site") or "").strip()
    if not site:
        return jsonify({"ok": False, "error": "Missing ?site="}), 400
    ok = remove_site(site)
    return jsonify({"ok": ok, "sites": get_all_sites()})
 
 
@app.route("/clearsites", methods=["POST"])
def api_clear_sites():
    clear_all_sites()
    return jsonify({"ok": True, "sites": []})
 
 
# ── Site check ────────────────────────────────────────────────────────────────
 
@app.route("/sitecheck", methods=["GET", "POST"])
def api_site_check():
    data    = request.get_json(silent=True) or request.args.to_dict()
    site    = (data.get("site") or "").strip()
    proxy   = (data.get("proxy") or "").strip() or None
    chat_id = data.get("chat_id")
 
    if not site:
        return jsonify({"ok": False, "error": "Missing ?site="}), 400
 
    if not proxy:
        proxy = _load_proxy_from_file()
 
    result = check_site_status(site, chat_id=chat_id, received_proxy=proxy)
    return jsonify(result)
 
 
@app.route("/sitecheckfile", methods=["POST"])
def api_site_check_file():
    """
    POST JSON: {"file": "/absolute/path/to/domains.txt", "workers": 3}
    Runs bulk check_sites_from_file() and returns summary.
    Only usable when the file is already on disk (e.g. uploaded via Replit).
    """
    data     = request.get_json(silent=True) or {}
    file_path = data.get("file", "").strip()
    workers  = int(data.get("workers", 3))
    proxy    = (data.get("proxy") or "").strip() or None
    chat_id  = data.get("chat_id")
 
    if not file_path:
        return jsonify({"ok": False, "error": "Missing 'file' field"}), 400
    if not os.path.exists(file_path):
        return jsonify({"ok": False, "error": f"File not found: {file_path}"}), 400
 
    if not proxy:
        proxy = _load_proxy_from_file()
 
    result = check_sites_from_file(
        file_path,
        chat_id=chat_id,
        received_proxy=proxy,
        max_workers=workers,
    )
    return jsonify(result)
 
 
# ── Health ────────────────────────────────────────────────────────────────────
 
@app.route("/health", methods=["GET"])
def health():
    return jsonify({
        "ok":    True,
        "sites": len(get_all_sites()),
        "time":  time.strftime("%Y-%m-%d %H:%M:%S"),
    })
 
 
@app.route("/", methods=["GET"])
def root():
    return jsonify({
        "name": "Stripe Auth API",
        "endpoints": {
            "check":      "GET /stripe?cc=CC|MM|YY|CVV&site=example.com&proxy=ip:port:user:pass",
            "sites":      "GET /sites",
            "add_site":   "POST /addsite?site=example.com",
            "remove":     "POST /removesite?site=example.com",
            "clear":      "POST /clearsites",
            "site_check": "GET /sitecheck?site=example.com",
            "bulk_check": "POST /sitecheckfile {file, workers, proxy}",
            "health":     "GET /health",
        }
    })
 
 
# ── Entry ─────────────────────────────────────────────────────────────────────
 
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    log.info(f"Starting Stripe Auth API on port {port}")
    log.info(f"Sites configured: {get_all_sites()}")
    app.run(host="0.0.0.0", port=port, threaded=True)
