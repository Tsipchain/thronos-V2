import os, json, time, hashlib
from fpdf import FPDF
from flask import request, jsonify
from phantom_gateway_mainnet import get_btc_txns  # δικό σου API
from dynamic_thr_fee import calculate_dynamic_fee  # Importing dynamic fee calculation


CHAIN_FILE = "phantom_tx_chain.json"
BTC_RECEIVER = "1FQov4P8yzUU1Af4C5QNyAfQauc4maytKo"
CONTRACTS_DIR = "templates/contracts"

os.makedirs(CONTRACTS_DIR, exist_ok=True)

def generate_thr_address():
    return f"THR{int(time.time()*1000)}"

def create_pdf_contract(btc_address, pledge_text, thr_address, filename):
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Courier", size=12)
    pdf.multi_cell(0, 10, f"BTC Address: {btc_address}\n\nPledge:\n{pledge_text}\n\nGenerated THR Address:\n{thr_address}")
    pdf.output(os.path.join(CONTRACTS_DIR, filename))

def handle_pledge_submission():
    data = request.get_json()
    btc_address = data.get("btc_address")
    pledge_text = data.get("pledge_text", "Default pledge to the Thronos Chain.")

    # Έλεγχος πληρωμής στο Blockstream (mock ή πραγματικός)
    txns = get_btc_txns(btc_address)
    valid_payment = any(tx.get("to") == BTC_RECEIVER and float(tx.get("amount_btc", 0)) >= 0.00001 for tx in txns)

    if not valid_payment:
        return jsonify({"status": "pending", "message": "No valid BTC payment yet."})

    # Δημιουργία THR address και block
    thr_address = generate_thr_address()
    pledge_hash = hashlib.sha256((btc_address + pledge_text).encode()).hexdigest()
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S")

    block = {
        "btc_address": btc_address,
        "pledge_text": pledge_text,
        "timestamp": timestamp,
        "pledge_hash": pledge_hash,
        "thr_address": thr_address
    }

    # Εγγραφή στο JSON chain
    if not os.path.exists(CHAIN_FILE):
        with open(CHAIN_FILE, "w") as f: json.dump([], f)
    with open(CHAIN_FILE, "r") as f: chain = json.load(f)
    chain.append(block)
    with open(CHAIN_FILE, "w") as f: json.dump(chain, f, indent=2)

    # Δημιουργία PDF
    pdf_name = f"pledge_{thr_address}.pdf"
    create_pdf_contract(btc_address, pledge_text, thr_address, pdf_name)

    return jsonify({
        "status": "verified",
        "thr_address": thr_address,
        "hash": pledge_hash,
        "pdf_filename": pdf_name
    })
