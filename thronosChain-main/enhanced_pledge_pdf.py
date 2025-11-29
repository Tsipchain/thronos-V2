import os, json, time, hashlib
from fpdf import FPDF
from flask import request, jsonify
from phantom_gateway_mainnet import get_btc_txns
import qrcode
from PIL import Image
from io import BytesIO

CHAIN_FILE = "phantom_tx_chain.json"
BTC_RECEIVER = "1QFeDPwEF8yEgPEfP79hpc8pHytXMz9oEQ"
CONTRACTS_DIR = "templates/contracts"
PHANTOM_IMAGE = "phantomface_base.png"

os.makedirs(CONTRACTS_DIR, exist_ok=True)

def generate_thr_address():
    return f"THR{int(time.time()*1000)}"

def embed_stego_image(data_hash, out_path):
    try:
        base_img = Image.open(PHANTOM_IMAGE).convert("RGB")
        pixels = base_img.load()
        for i in range(len(data_hash)):
            x = i % base_img.width
            y = i // base_img.width
            if y < base_img.height:
                r, g, b = pixels[x, y]
                pixels[x, y] = (r & ~1 | int(data_hash[i], 16) & 1, g, b)
        base_img.save(out_path)
    except Exception as e:
        print("[Stego Error]", e)

def generate_qr_image(content):
    qr = qrcode.QRCode(version=1, box_size=2, border=1)
    qr.add_data(content)
    qr.make(fit=True)
    img = qr.make_image(fill="black", back_color="white")
    buf = BytesIO()
    img.save(buf, format="PNG")
    buf.seek(0)
    return buf

def create_pdf_contract(btc_address, pledge_text, thr_address, filename, block_height):
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Courier", size=12)
    
    pdf.multi_cell(0, 10, f"BTC Address: {btc_address}\n\nPledge:\n{pledge_text}\n\nGenerated THR Address:\n{thr_address}")

    # Generate hash and QR
    pledge_hash = hashlib.sha256((btc_address + pledge_text).encode()).hexdigest()
    qr_buf = generate_qr_image(f"hash:{pledge_hash}, height:{block_height}")
    qr_path = os.path.join(CONTRACTS_DIR, f"qr_{thr_address}.png")
    with open(qr_path, "wb") as f:
        f.write(qr_buf.read())
    pdf.image(qr_path, x=150, y=250, w=40)

    # Steganography image
    stego_path = os.path.join(CONTRACTS_DIR, f"stego_{thr_address}.png")
    embed_stego_image(pledge_hash, stego_path)
    pdf.image(stego_path, x=10, y=250, w=40)

    pdf.output(os.path.join(CONTRACTS_DIR, filename))

def handle_pledge_submission():
    data = request.get_json()
    btc_address = data.get("btc_address")
    pledge_text = data.get("pledge_text", "Default pledge to the Thronos Chain.")

    txns = get_btc_txns(btc_address)
    valid_payment = any(tx.get("to") == BTC_RECEIVER and float(tx.get("amount_btc", 0)) >= 0.00001 for tx in txns)

    if not valid_payment:
        return jsonify({"status": "pending", "message": "No valid BTC payment yet."})

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

    chain = []
    if os.path.exists(CHAIN_FILE):
        with open(CHAIN_FILE, "r") as f:
            chain = json.load(f)
    chain.append(block)
    with open(CHAIN_FILE, "w") as f:
        json.dump(chain, f, indent=2)

    pdf_name = f"pledge_{thr_address}.pdf"
    create_pdf_contract(btc_address, pledge_text, thr_address, pdf_name, len(chain))

    return jsonify({
        "status": "verified",
        "thr_address": thr_address,
        "hash": pledge_hash,
        "pdf_filename": pdf_name
    })
