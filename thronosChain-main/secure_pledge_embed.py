# secure_pledge_embed.py
# Δημιουργεί secure PDF + stego PNG για κάθε pledge
# - AES/EAX encrypt το pledge_text
# - QR με THR address + height
# - base image + stego overlay
# - περιλαμβάνει και το send_seed στο PDF

import os
import io
import base64
import json
import time
import hashlib
from pathlib import Path

from Cryptodome.Cipher import AES
from Cryptodome.Random import get_random_bytes


from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import A4
from reportlab.lib.units import mm
from reportlab.lib.utils import ImageReader

from PIL import Image
import qrcode


BASE_DIR   = os.path.dirname(os.path.abspath(__file__))
DATA_DIR   = os.path.join(BASE_DIR, "data")
ASSETS_DIR = os.path.join(BASE_DIR, "assets")

# default contracts dir (αν δεν δωθεί output_dir από server)
DEFAULT_CONTRACTS_DIR = os.path.join(DATA_DIR, "contracts")
os.makedirs(DEFAULT_CONTRACTS_DIR, exist_ok=True)

BASE_IMAGE = os.path.join(ASSETS_DIR, "phantom_base.png")


def aes_encrypt_to_b64(plaintext: str) -> str:
    key = get_random_bytes(32)
    cipher = AES.new(key, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext.encode("utf-8"))
    blob = {
        "key": base64.b64encode(key).decode(),
        "nonce": base64.b64encode(cipher.nonce).decode(),
        "tag": base64.b64encode(tag).decode(),
        "cipher": base64.b64encode(ciphertext).decode(),
    }
    return base64.b64encode(json.dumps(blob).encode()).decode()


def make_qr_image(data: str) -> Image.Image:
    qr = qrcode.QRCode(
        error_correction=qrcode.constants.ERROR_CORRECT_M,
        box_size=8,
        border=2,
    )
    qr.add_data(data)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")
    return img.convert("RGB")


def embed_stego(base_img: Image.Image, payload: str) -> Image.Image:
    # Πολύ απλό LSB stego για demo
    data_bits = "".join(f"{ord(c):08b}" for c in payload)
    px = base_img.load()
    w, h = base_img.size
    idx = 0
    for y in range(h):
        for x in range(w):
            if idx >= len(data_bits):
                return base_img
            r, g, b = px[x, y]
            b = (b & ~1) | int(data_bits[idx])
            px[x, y] = (r, g, b)
            idx += 1
    return base_img


def create_secure_pdf_contract(
    btc_address: str,
    pledge_text: str,
    thr_address: str,
    pledge_hash: str,
    height: int,
    send_seed: str,
    output_dir: str = None,
) -> str:
    """
    Φτιάχνει:
      - stego PNG: phantom_<thr>.png
      - PDF: pledge_<thr>.pdf
    Επιστρέφει μόνο το PDF filename.
    """
    if output_dir is None:
        output_dir = DEFAULT_CONTRACTS_DIR
    os.makedirs(output_dir, exist_ok=True)

    node_id   = "CPE_GATEWAY"
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime())

    # 1) Encrypted pledge (AES/EAX/base64)
    encrypted_blob = aes_encrypt_to_b64(pledge_text)

    # 2) QR με πληροφορίες block
    qr_payload = json.dumps({
        "thr_address": thr_address,
        "height": height,
        "node": node_id,
        "ts": timestamp,
        "pledge_hash": pledge_hash,
    })
    qr_img = make_qr_image(qr_payload)

    # 3) Stego base image + QR payload
    if os.path.exists(BASE_IMAGE):
        base_img = Image.open(BASE_IMAGE).convert("RGB")
    else:
        # fallback: απλό λευκό
        base_img = Image.new("RGB", (800, 800), "white")

    stego_payload = json.dumps({
        "thr_address": thr_address,
        "pledge_hash": pledge_hash,
        "encrypted_blob": encrypted_blob,
        "send_seed_hint_sha": hashlib.sha256(send_seed.encode()).hexdigest(),
    })
    stego_img = embed_stego(base_img, stego_payload)

    stego_filename = f"phantom_{thr_address}.png"
    stego_path     = os.path.join(output_dir, stego_filename)
    stego_img.save(stego_path, "PNG")

    # 4) PDF
    pdf_filename = f"pledge_{thr_address}.pdf"
    pdf_path     = os.path.join(output_dir, pdf_filename)

    c = canvas.Canvas(pdf_path, pagesize=A4)
    w, h = A4

    y = h - 20 * mm
    c.setFont("Helvetica-Bold", 16)
    c.drawString(20 * mm, y, "THRONOS BLOCKCHAIN PLEDGE CONTRACT")
    y -= 10 * mm

    c.setFont("Helvetica", 11)
    c.drawString(20 * mm, y, f"Time: {timestamp}")
    y -= 6 * mm
    c.drawString(20 * mm, y, f"Node: {node_id}")
    y -= 6 * mm
    c.drawString(20 * mm, y, f"BTC Address (KYC): {btc_address}")
    y -= 6 * mm
    c.drawString(20 * mm, y, f"THR Address: {thr_address}")
    y -= 6 * mm
    c.drawString(20 * mm, y, f"Pledge Hash: {pledge_hash}")
    y -= 10 * mm

    c.setFont("Helvetica-Bold", 12)
    c.drawString(20 * mm, y, "Pledge:")
    y -= 6 * mm

    c.setFont("Helvetica", 11)
    text_obj = c.beginText(25 * mm, y)
    text_obj.setLeading(4.2 * mm)
    for word_line in pledge_text.split("\n"):
        text_obj.textLine(word_line)
    c.drawText(text_obj)
    y -= 25 * mm

    c.setFont("Helvetica-Bold", 12)
    c.drawString(20 * mm, y, "Encrypted (AES/EAX/base64):")
    y -= 6 * mm

    c.setFont("Helvetica", 8)
    text_obj2 = c.beginText(20 * mm, y)
    text_obj2.setLeading(4 * mm)
    for i in range(0, len(encrypted_blob), 80):
        text_obj2.textLine(encrypted_blob[i:i+80])
    c.drawText(text_obj2)
    y -= 35 * mm

    # Send Seed section
    c.setFont("Helvetica-Bold", 12)
    c.drawString(20 * mm, y, "Send Seed (KEEP THIS SECRET):")
    y -= 6 * mm
    c.setFont("Helvetica", 10)
    c.drawString(20 * mm, y, send_seed)
    y -= 12 * mm
    c.setFont("Helvetica", 8)
    c.drawString(20 * mm, y, "Use this seed in the Send THR page as auth_secret.")
    y -= 15 * mm

    # QR on PDF
    qr_buf = io.BytesIO()
    qr_img.save(qr_buf, format="PNG")
    qr_buf.seek(0)
    qr_reader = ImageReader(qr_buf)
    c.drawImage(qr_reader, 20 * mm, 20 * mm, width=50 * mm, height=50 * mm)

    # Stego preview (μικρό)
    stego_buf = io.BytesIO()
    stego_img.save(stego_buf, format="PNG")
    stego_buf.seek(0)
    stego_reader = ImageReader(stego_buf)
    c.drawImage(stego_reader, 80 * mm, 20 * mm, width=80 * mm, height=80 * mm)

    c.showPage()
    c.save()

    return pdf_filename
