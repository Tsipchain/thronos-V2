# server.py
# Full-featured ThronosChain server with pledge, PDF, wallet, token dynamics + data volume + whitelist admin

import os
import json
import time
import hashlib
import logging
import requests

from flask import (
    Flask, request, jsonify,
    render_template, send_from_directory,
    redirect, url_for
)
from phantom_gateway_mainnet import get_btc_txns
from apscheduler.schedulers.background import BackgroundScheduler

# Χρησιμοποιούμε το secure_pledge_embed για AES + QR + stego PDF
from secure_pledge_embed import create_secure_pdf_contract

# ─── CONFIG ────────────────────────────────────────
app = Flask(__name__)

BASE_DIR   = os.path.dirname(os.path.abspath(__file__))
STATIC_DIR = os.path.join(BASE_DIR, "static")
DATA_DIR   = os.path.join(BASE_DIR, "data")

# Volume στο Railway: /app/data
os.makedirs(DATA_DIR, exist_ok=True)

LEDGER_FILE   = os.path.join(DATA_DIR, "ledger.json")
CHAIN_FILE    = os.path.join(DATA_DIR, "phantom_tx_chain.json")
PLEDGE_CHAIN  = os.path.join(DATA_DIR, "pledge_chain.json")

# Whitelist για free pledges (χωρίς BTC)
WHITELIST_FILE = os.path.join(DATA_DIR, "free_pledge_whitelist.json")
ADMIN_SECRET   = os.getenv("ADMIN_SECRET", "CHANGE_ME_NOW")

BTC_RECEIVER  = "1QFeDPwEF8yEgPEfP79hpc8pHytXMz9oEQ"
MIN_AMOUNT    = 0.00001

CONTRACTS_DIR = os.path.join(STATIC_DIR, "contracts")
os.makedirs(CONTRACTS_DIR, exist_ok=True)

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("pledge")

# ─── HELPERS ───────────────────────────────────────
def load_json(path, default):
    try:
        with open(path, "r") as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return default

def save_json(path, data):
    # μικρό safety: δημιουργεί parent dirs αν δεν υπάρχουν
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        json.dump(data, f, indent=2)

def calculate_reward(height: int) -> float:
    halvings = height // 210000
    return round(1.0 / (2 ** halvings), 6)

# ─── ROUTES ─────────────────────────────────────────
@app.route("/")
def home():
    return render_template("index.html")

@app.route("/contracts/<path:filename>")
def serve_contract(filename):
    # Σερβίρει PDF + PNG από static/contracts
    return send_from_directory(CONTRACTS_DIR, filename)

@app.route("/pledge")
def pledge_form():
    return render_template("pledge_form.html")

@app.route("/pledge_submit", methods=["POST"])
def pledge_submit():
    data = request.get_json() or {}
    btc_address = data.get("btc_address", "").strip()
    pledge_text = data.get("pledge_text", "").strip()

    if not btc_address:
        return jsonify(error="Missing BTC address"), 400

    pledges = load_json(PLEDGE_CHAIN, [])
    exists = next((p for p in pledges if p["btc_address"] == btc_address), None)
    if exists:
        # PDF όνομα με βάση το THR address
        return jsonify(
            status="already_verified",
            thr_address=exists["thr_address"],
            pledge_hash=exists["pledge_hash"],
            pdf_filename=f"pledge_{exists['thr_address']}.pdf",
        ), 200

    # --- BTC verification ή free mode με whitelist ---
    free_list = load_json(WHITELIST_FILE, [])
    is_dev_free = btc_address in free_list

    if is_dev_free:
        paid = True
        txns = []  # δεν χρειάζεται call στο explorer
    else:
        txns = get_btc_txns(btc_address, BTC_RECEIVER)
        paid = any(
            tx["to"] == BTC_RECEIVER and tx["amount_btc"] >= MIN_AMOUNT
            for tx in txns
        )

    if not paid:
        return jsonify(
            status="pending",
            message="Waiting for BTC payment",
            txns=txns,
        ), 200

    # Δημιουργία THR address + pledge hash
    thr_addr = f"THR{int(time.time() * 1000)}"
    phash = hashlib.sha256((btc_address + pledge_text).encode()).hexdigest()

    pledges.append({
        "btc_address": btc_address,
        "pledge_text": pledge_text,
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime()),
        "pledge_hash": phash,
        "thr_address": thr_addr,
    })
    save_json(PLEDGE_CHAIN, pledges)

    # Ύψος chain για το QR
    chain = load_json(CHAIN_FILE, [])
    height = len(chain)

    # Δημιουργία secure PDF (AES + QR + stego PNG)
    pdf_name = create_secure_pdf_contract(
        btc_address=btc_address,
        pledge_text=pledge_text,
        thr_address=thr_addr,
        pledge_hash=phash,
        height=height,
    )

    return jsonify(
        status="verified",
        thr_address=thr_addr,
        pledge_hash=phash,
        pdf_filename=pdf_name,
    ), 200

@app.route("/viewer")
def viewer():
    return render_template("thronos_block_viewer.html")

@app.route("/chain")
def get_chain():
    return jsonify(load_json(CHAIN_FILE, [])), 200

@app.route("/last_block_hash")
def last_block_hash():
    chain = load_json(CHAIN_FILE, [])
    return jsonify(
        last_hash=chain[-1]["block_hash"] if chain else "0" * 64
    )

@app.route("/submit_block", methods=["POST"])
def submit_block():
    data = request.get_json() or {}
    chain = load_json(CHAIN_FILE, [])
    h = len(chain)
    r = calculate_reward(h)
    fee = 0.005

    data.setdefault(
        "timestamp",
        time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime()),
    )
    data.setdefault("block_hash", f"THR-{h}")
    data["reward"] = r
    data["pool_fee"] = fee
    data["reward_to_miner"] = round(r - fee, 6)

    # enrich από pledge_chain
    pledges = load_json(PLEDGE_CHAIN, [])
    match = next(
        (p for p in pledges if p.get("thr_address") == data.get("thr_address")),
        None,
    )
    if match:
        data.update({
            "miner_btc_address": match.get("btc_address"),
            "pledge_text": match.get("pledge_text"),
            "pledge_hash": match.get("pledge_hash"),
        })

    chain.append(data)
    save_json(CHAIN_FILE, chain)

    # Ledger / balances
    ledger = load_json(LEDGER_FILE, {})
    miner = data["thr_address"]
    ledger[miner] = round(
        ledger.get(miner, 0.0) + data["reward_to_miner"],
        6,
    )
    save_json(LEDGER_FILE, ledger)

    return jsonify(status="ok", **data), 200

@app.route("/wallet")
def wallet_page():
    return render_template("wallet_viewer.html")

@app.route("/wallet_data/<thr_addr>")
def wallet_data(thr_addr):
    ledger  = load_json(LEDGER_FILE, {})
    chain   = load_json(CHAIN_FILE, [])
    bal     = round(ledger.get(thr_addr, 0.0), 6)
    history = [
        tx for tx in chain
        if isinstance(tx, dict) and (
            tx.get("from") == thr_addr or tx.get("to") == thr_addr
        )
    ]
    return jsonify(balance=bal, transactions=history), 200

@app.route("/wallet/<thr_addr>")
def wallet_redirect(thr_addr):
    return redirect(url_for("wallet_data", thr_addr=thr_addr)), 302

# ─── ADMIN WHITELIST ENDPOINTS ─────────────────────

@app.route("/admin/whitelist", methods=["GET"])
def admin_whitelist_page():
    """
    Simple admin UI για whitelist.
    Απαιτεί ?secret=ADMIN_SECRET στο URL, αλλιώς 403.
    """
    secret = request.args.get("secret", "")
    if secret != ADMIN_SECRET:
        return "Forbidden (wrong or missing secret)", 403

    # Θα περαστεί στο template ώστε το JS να καλεί τα JSON endpoints
    return render_template("admin_whitelist.html", admin_secret=secret)

@app.route("/admin/whitelist/add", methods=["POST"])
def admin_whitelist_add():
    data = request.get_json() or {}
    if data.get("secret") != ADMIN_SECRET:
        return jsonify(error="forbidden"), 403

    btc = (data.get("btc_address") or "").strip()
    if not btc:
        return jsonify(error="missing btc_address"), 400

    wl = load_json(WHITELIST_FILE, [])
    if btc not in wl:
        wl.append(btc)
        save_json(WHITELIST_FILE, wl)

    return jsonify(status="ok", whitelist=wl), 200


@app.route("/admin/whitelist/list", methods=["GET"])
def admin_whitelist_list():
    secret = request.args.get("secret", "")
    if secret != ADMIN_SECRET:
        return jsonify(error="forbidden"), 403

    wl = load_json(WHITELIST_FILE, [])
    return jsonify(whitelist=wl), 200

# ─── BACKGROUND MINTER ─────────────────────────────
def mint_first_blocks():
    pledges = load_json(PLEDGE_CHAIN, [])
    chain   = load_json(CHAIN_FILE, [])
    seen    = {
        b.get("thr_address")
        for b in chain
        if isinstance(b, dict) and b.get("thr_address")
    }
    height  = len(chain)

    for p in pledges:
        thr = p["thr_address"]
        if thr in seen:
            continue

        r   = calculate_reward(height)
        fee = 0.005
        to_miner = round(r - fee, 6)

        block = {
            "thr_address": thr,
            "timestamp": time.strftime(
                "%Y-%m-%d %H:%M:%S UTC",
                time.gmtime(),
            ),
            "block_hash": f"THR-{height}",
            "reward": r,
            "pool_fee": fee,
            "reward_to_miner": to_miner,
        }

        try:
            port = int(os.getenv("PORT", 3333))
            url  = f"http://localhost:{port}/submit_block"
            requests.post(url, json=block, timeout=5).raise_for_status()
            chain = load_json(CHAIN_FILE, [])
            height = len(chain)
            seen.add(thr)
            print(f"⛏️ Mined block #{height} for {thr}: +{to_miner} THR")
        except Exception as e:
            print(f"❌ Failed mining for {thr}:", e)

scheduler = BackgroundScheduler(daemon=True)
scheduler.add_job(mint_first_blocks, 'interval', minutes=1)
scheduler.start()

if __name__ == "__main__":
    port = int(os.getenv("PORT", 3333))
    app.run(host="0.0.0.0", port=port)
