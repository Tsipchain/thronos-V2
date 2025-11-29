# server.py
# Full-featured ThronosChain server with pledge, PDF, wallet,
# token dynamics, secure PDF (AES+QR+stego) και backup/restore endpoints.

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

from phantom_gateway_mainnet import get_btc_txns          # BTC check
from secure_pledge_embed import create_secure_pdf_contract  # AES+QR+stego PDF :contentReference[oaicite:2]{index=2}
from apscheduler.schedulers.background import BackgroundScheduler

# ─── CONFIG ────────────────────────────────────────
app = Flask(__name__)
STATIC_DIR    = os.path.join(app.root_path, "static")
LEDGER_FILE   = os.path.join(STATIC_DIR, "ledger.json")
CHAIN_FILE    = os.path.join(STATIC_DIR, "phantom_tx_chain.json")
PLEDGE_CHAIN  = os.path.join(STATIC_DIR, "pledge_chain.json")
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
    except FileNotFoundError:
        return default

def save_json(path, data):
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
    # θα σερβίρει τα PDFs + stego από static/contracts
    return send_from_directory(CONTRACTS_DIR, filename)

@app.route("/pledge")
def pledge_form():
    return render_template("pledge_form.html")

@app.route("/pledge_submit", methods=["POST"])
def pledge_submit():
    """
    Πλήρες pledge flow:
    - ελέγχει BTC πληρωμή
    - δημιουργεί THR address
    - γράφει pledge_chain.json
    - δημιουργεί SECURE PDF (AES+QR+stego)
    """
    data = request.get_json() or {}
    btc_address = data.get("btc_address", "").strip()
    pledge_text = data.get("pledge_text", "").strip()

    if not btc_address:
        return jsonify(error="Missing BTC address"), 400

    pledges = load_json(PLEDGE_CHAIN, [])
    exists = next((p for p in pledges if p["btc_address"] == btc_address), None)
    if exists:
        pdf_name = f"pledge_{exists['thr_address']}.pdf"
        return jsonify(
            status="already_verified",
            thr_address=exists["thr_address"],
            pledge_hash=exists["pledge_hash"],
            pdf_filename=pdf_name
        ), 200

    # BTC check προς Blockstream/phantom gateway :contentReference[oaicite:3]{index=3}
    txns = get_btc_txns(btc_address, BTC_RECEIVER)
    paid = any(
        tx.get("to") == BTC_RECEIVER and float(tx.get("amount_btc", 0)) >= MIN_AMOUNT
        for tx in txns
    )
    if not paid:
        return jsonify(status="pending", message="Waiting for BTC payment", txns=txns), 200

    # Δημιουργία THR address + pledge hash
    thr_addr = f"THR{int(time.time()*1000)}"
    phash = hashlib.sha256((btc_address + pledge_text).encode()).hexdigest()

    pledges.append({
        "btc_address": btc_address,
        "pledge_text": pledge_text,
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime()),
        "pledge_hash": phash,
        "thr_address": thr_addr
    })
    save_json(PLEDGE_CHAIN, pledges)

    # Υψος chain για το secure PDF (ώστε να μπαίνει μέσα και το height)
    chain = load_json(CHAIN_FILE, [])
    height = len(chain)

    # SECURE PDF: AES + QR + stego εικόνα μέσα στο PDF :contentReference[oaicite:4]{index=4}
    pdf_name = create_secure_pdf_contract(
        btc_address=btc_address,
        pledge_text=pledge_text,
        thr_address=thr_addr,
        pledge_hash=phash,
        height=height
    )

    return jsonify(
        status="verified",
        thr_address=thr_addr,
        pledge_hash=phash,
        pdf_filename=pdf_name
    ), 200

@app.route("/viewer")
def viewer():
    return render_template("thronos_block_viewer.html")

@app.route("/chain")
def get_chain():
    return jsonify(load_json(CHAIN_FILE, [])), 200

# Πλήρες chain ως raw JSON για backup από το CPE
@app.route("/backup/chain", methods=["GET"])
def backup_chain():
    chain = load_json(CHAIN_FILE, [])
    return app.response_class(
        response=json.dumps(chain, indent=2),
        status=200,
        mimetype="application/json"
    )

@app.route("/last_block_hash")
def last_block_hash():
    chain = load_json(CHAIN_FILE, [])
    return jsonify(last_hash=chain[-1]["block_hash"] if chain else "0"*64)

@app.route("/submit_block", methods=["POST"])
def submit_block():
    data = request.get_json() or {}
    chain = load_json(CHAIN_FILE, [])
    height = len(chain)

    r = calculate_reward(height)
    fee = 0.005
    data.setdefault("timestamp", time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime()))
    data.setdefault("block_hash", f"THR-{height}")
    data["reward"] = r
    data["pool_fee"] = fee
    data["reward_to_miner"] = round(r - fee, 6)

    # enrich με στοιχεία pledge, αν υπάρχουν :contentReference[oaicite:5]{index=5}
    pledges = load_json(PLEDGE_CHAIN, [])
    match = next((p for p in pledges if p.get("thr_address") == data.get("thr_address")), None)
    if match:
        data.update({
            "miner_btc_address": match.get("btc_address"),
            "pledge_text": match.get("pledge_text"),
            "pledge_hash": match.get("pledge_hash")
        })

    chain.append(data)
    save_json(CHAIN_FILE, chain)

    # ledger update
    ledger = load_json(LEDGER_FILE, {})
    miner = data["thr_address"]
    ledger[miner] = round(ledger.get(miner, 0.0) + data["reward_to_miner"], 6)
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
        if isinstance(tx, dict) and (tx.get("from") == thr_addr or tx.get("to") == thr_addr or tx.get("thr_address") == thr_addr)
    ]
    return jsonify(balance=bal, transactions=history), 200

@app.route("/wallet/<thr_addr>")
def wallet_redirect(thr_addr):
    return redirect(url_for("wallet_data", thr_addr=thr_addr)), 302

# Endpoint για restore του chain μετά από redeploy
@app.route("/restore_chain", methods=["POST"])
def restore_chain():
    """
    Δέχεται πλήρες chain JSON από backup (CPE / PC)
    και ξαναχτίζει phantom_tx_chain.json + ledger.json.
    """
    data = request.get_json() or []
    if not isinstance(data, list):
        return jsonify(error="chain must be a list"), 400

    # γράφουμε το chain
    save_json(CHAIN_FILE, data)

    # χτίζουμε ledger από την αρχή
    ledger = {}
    for block in data:
        if not isinstance(block, dict):
            continue
        thr_addr = block.get("thr_address")
        reward_to_miner = float(block.get("reward_to_miner", 0.0))
        if thr_addr:
            ledger[thr_addr] = round(ledger.get(thr_addr, 0.0) + reward_to_miner, 6)

    save_json(LEDGER_FILE, ledger)

    return jsonify(status="restored", height=len(data), wallets=len(ledger)), 200

# ─── BACKGROUND JOB: αυτόματο minting για pledges χωρίς block ─────────
def mint_first_blocks():
    pledges = load_json(PLEDGE_CHAIN, [])
    chain   = load_json(CHAIN_FILE, [])
    seen    = {b.get("thr_address") for b in chain if isinstance(b, dict) and b.get("thr_address")}
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
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime()),
            "block_hash": f"THR-{height}",
            "reward": r,
            "pool_fee": fee,
            "reward_to_miner": to_miner
        }

        try:
            # local submit στον ίδιο server
            port = int(os.getenv("PORT", 3333))
            resp = requests.post(f"http://127.0.0.1:{port}/submit_block", json=block, timeout=5)
            resp.raise_for_status()
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
    # Railway: web service θα τρέχει αυτό
    app.run(host="0.0.0.0", port=port)
