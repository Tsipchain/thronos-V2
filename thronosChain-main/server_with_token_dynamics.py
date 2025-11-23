import os
import json
import time
import hashlib
from flask import Flask, request, jsonify, render_template, send_from_directory
from phantom_gateway_mainnet import get_btc_txns
from token_dynamics import TokenDynamics, enhance_pdf_contract

# Initialize Flask app
app = Flask(__name__)

# ─── CONFIG ────────────────────────────────────────
LEDGER_FILE   = "ledger.json"
CHAIN_FILE    = "phantom_tx_chain.json"
PLEDGE_CHAIN  = "pledge_chain.json"
BTC_RECEIVER  = "1FQov4P8yzUU1Af4C5QNyAfQauc4maytKo"
CONTRACTS_DIR = os.path.join(app.root_path, "contracts")
os.makedirs(CONTRACTS_DIR, exist_ok=True)

# Initialize token dynamics tracker
token_dynamics = TokenDynamics()

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

def calculate_reward(block_height: int) -> float:
    halvings = block_height // 210000
    base_reward = 1.0
    return round(base_reward / (2 ** halvings), 6)

# ─── TEMPLATE ROUTES ──────────────────────────────
@app.route("/")
def home():
    return render_template("index.html")

@app.route("/docs")
def docs():
    return render_template("tokenomics.html")

@app.route("/pledge")
def pledge_form():
    return render_template("pledge_form.html")

@app.route("/send")
def send_thr_form():
    return render_template("send_thr_form.html")

@app.route("/viewer")
def block_viewer():
    return render_template("thronos_block_viewer.html")

@app.route("/wallet")
def wallet_viewer():
    return render_template("wallet_viewer.html")

# ─── TOKEN DYNAMICS ROUTES ──────────────────────────
@app.route("/token_chart")
def token_chart():
    # Generate a new chart with the latest data
    token_dynamics.generate_price_chart()
    return render_template("token_chart.html")

@app.route("/api/token/value")
def get_token_value():
    # Get current token value
    current_value = token_dynamics.get_current_thr_value()
    return jsonify({
        "thr_value_btc": current_value,
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime())
    })

# ─── PLEDGE ENDPOINT ───────────────────────────────
@app.route("/pledge_submit", methods=["POST"])
def pledge_submit():
    data        = request.get_json() or {}
    btc_address = data.get("btc_address", "").strip()
    pledge_text = data.get("pledge_text", "").strip()

    if not btc_address:
        return jsonify(error="Missing BTC address"), 400

    pledges = load_json(PLEDGE_CHAIN, [])

    existing = next((p for p in pledges if p["btc_address"] == btc_address), None)
    if existing:
        # Get token value info even for existing pledges
        token_value_info = token_dynamics.get_thr_value_for_pledge(0.00001)
        
        return jsonify({
            "status":       "already_verified",
            "thr_address":  existing["thr_address"],
            "pledge_hash":  existing["pledge_hash"],
            "pdf_filename": f"pledge_{existing['thr_address']}.pdf",
            "token_dynamics": {
                "current_thr_value": token_value_info['thr_rate'],
                "thr_equivalent": token_value_info['thr_equivalent'],
                "price_chart_url": "/static/thr_price_chart.png"
            }
        }), 200

    # Check if address exists in blockchain
    chain = load_json(CHAIN_FILE, [])
    address_in_chain = any(block.get('thr_address') == btc_address for block in chain if isinstance(block, dict))
    
    # Verify payment
    # If address exists in blockchain, skip verification
    txns = get_btc_txns(btc_address, BTC_RECEIVER, skip_verification=address_in_chain)
    paid = any(
        tx.get("to") == BTC_RECEIVER and float(tx.get("amount_btc", 0)) >= 0.00001
        for tx in txns
    )
    
    if not paid:
        return jsonify(status="pending",
                      message="Waiting for BTC payment to the pledge address."), 200

    # Get the BTC amount from the transaction
    btc_amount = 0.00001  # Default minimum amount
    for tx in txns:
        if tx.get("to") == BTC_RECEIVER:
            tx_amount = float(tx.get("amount_btc", 0))
            if tx_amount > btc_amount:
                btc_amount = tx_amount

    # Calculate token value information
    token_value_info = token_dynamics.get_thr_value_for_pledge(btc_amount)
    
    # Update token price based on this pledge
    token_dynamics.update_thr_value(btc_amount, token_value_info['thr_equivalent'])
    
    # Generate price chart
    token_dynamics.generate_price_chart()

    # New pledge
    thr_address = f"THR{int(time.time()*1000)}"
    pledge_hash = hashlib.sha256((btc_address + pledge_text).encode()).hexdigest()
    timestamp   = time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime())

    new_pledge = {
        "btc_address": btc_address,
        "pledge_text": pledge_text,
        "timestamp":   timestamp,
        "pledge_hash": pledge_hash,
        "thr_address": thr_address,
        "btc_amount":  btc_amount,
        "thr_value":   token_value_info['thr_rate'],
        "thr_equivalent": token_value_info['thr_equivalent']
    }
    pledges.append(new_pledge)
    save_json(PLEDGE_CHAIN, pledges)

    pdf_name = f"pledge_{thr_address}.pdf"
    enhance_pdf_contract(btc_address, pledge_text, thr_address, pdf_name, token_value_info)

    return jsonify({
        "status":       "verified",
        "thr_address":  thr_address,
        "pledge_hash":  pledge_hash,
        "pdf_filename": pdf_name,
        "token_dynamics": {
            "current_thr_value": token_value_info['thr_rate'],
            "thr_equivalent": token_value_info['thr_equivalent'],
            "price_chart_url": "/static/thr_price_chart.png"
        }
    }), 200

# serve generated PDFs
@app.route("/contracts/<path:filename>")
def serve_contract(filename):
    return send_from_directory(CONTRACTS_DIR, filename)

# serve static files (including price charts)
@app.route("/static/<path:filename>")
def serve_static(filename):
    return send_from_directory(os.path.join(app.root_path, "static"), filename)

# ─── BLOCKCHAIN & TOKEN ENDPOINTS ────────────────
@app.route("/chain", methods=["GET"])
def get_chain():
    return jsonify(load_json(CHAIN_FILE, [])), 200

@app.route("/submit_block", methods=["POST"])
def submit_block():
    data = request.get_json()
    if not isinstance(data, dict):
        return jsonify(error="Invalid block data"), 400

    chain  = load_json(CHAIN_FILE, [])
    height = len(chain)

    reward   = calculate_reward(height)
    pool_fee = 0.005

    data.setdefault("timestamp",    time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime()))
    data.setdefault("block_hash",   f"THR-{height}")
    data["reward"]          = reward
    data["pool_fee"]        = pool_fee
    data["reward_to_miner"] = round(reward - pool_fee, 6)

    chain.append(data)
    save_json(CHAIN_FILE, chain)

    return jsonify({
        "status":         "ok",
        "block_hash":     data["block_hash"],
        "thr_address":    data.get("thr_address"),
        "reward":         reward,
        "reward_to_miner": data["reward_to_miner"]
    }), 200

@app.route("/wallet_data/<thr_address>", methods=["GET"])
def wallet_data(thr_address):
    ledger = load_json(LEDGER_FILE, {})
    chain  = load_json(CHAIN_FILE, [])
    balance = ledger.get(thr_address, 0.0)

    history = [
        tx for tx in chain
        if isinstance(tx, dict) and (
           tx.get("from")==thr_address or tx.get("to")==thr_address
        )
    ]
    
    # Add token value information
    token_value = token_dynamics.get_current_thr_value()
    btc_equivalent = balance * token_value
    
    return jsonify({
        "balance": round(balance, 6),
        "btc_equivalent": round(btc_equivalent, 8),
        "thr_value_in_btc": token_value,
        "transactions": history
    }), 200

@app.route("/send_token", methods=["POST"])
def send_token():
    data      = request.get_json() or {}
    sender    = data.get("from","").strip()
    recipient = data.get("to","").strip()
    try:
        amount = round(float(data.get("amount",0)),6)
    except:
        return jsonify(error="Invalid amount"), 400

    if not sender or not recipient or amount<=0:
        return jsonify(error="Invalid input"), 400

    ledger = load_json(LEDGER_FILE,{})
    fee    = 0.0015
    total  = round(amount+fee,6)
    if ledger.get(sender,0.0)<total:
        return jsonify(error="Insufficient balance"),403

    ledger[sender]    = round(ledger.get(sender,0.0)-total,6)
    ledger[recipient] = round(ledger.get(recipient,0.0)+amount,6)
    save_json(LEDGER_FILE,ledger)

    chain = load_json(CHAIN_FILE,[])
    tx = {
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime()),
        "from":      sender,
        "to":        recipient,
        "amount":    amount,
        "fee":       fee
    }
    chain.append(tx)
    save_json(CHAIN_FILE,chain)
    
    # Update token value after transaction
    token_dynamics.update_thr_value()

    return jsonify(status="OK", tx=tx),200

if __name__ == "__main__":
    # Ensure static directory exists
    os.makedirs(os.path.join(app.root_path, "static"), exist_ok=True)
    
    # Generate initial price chart if it doesn't exist
    token_dynamics.generate_price_chart()
    
    app.run(host="0.0.0.0", port=8000, debug=True)
