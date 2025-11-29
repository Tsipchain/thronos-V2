# secure_pledge_embed.py
# Δημιουργεί ασφαλές pledge PDF:
# - AES/EAX κρυπτογραφημένο payload
# - QR με node + THR + height
# - Stego εικόνα PIC OF THE FIRE με κρυμμένο send_seed

import os
import json
import base64
import hashlib
from io import BytesIO
import time

from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import A4
from reportlab.lib.units import inch

from PIL import Image
import qrcode

from Cryptodome.Cipher import AES
from Cryptodome.Random import get_random_bytes

BASE_DIR   = os.path.dirname(os.path.abspath(__file__))
STATIC_DIR = os.path.join(BASE_DIR, "static")

FIRE_IMG_PATH = os.path.join(STATIC_DIR, "PIC OF THE FIRE.png")


def _get_default_contracts_dir():
    return os.path.join(STATIC_DIR, "contracts")


os.makedirs(_get_default_contracts_dir(), exist_ok=True)


# ───────────── Stego helpers ───────────── #

def _embed_seed_in_fire_image(thr_address: str, send_seed: str, output_dir: str) -> str:
    """
    Κρύβει το send_seed μέσα στην εικόνα PIC OF THE FIRE με LSB steganography.
    Payload = {"thr_address": ..., "send_seed": ...}
    """
    payload = json.dumps(
        {"thr_address": thr_address, "send_seed": send_seed},
        sort_keys=True,
    ).encode("utf-8") + b"\0"  # null-terminated

    bits = "".join(f"{b:08b}" for b in payload)

    img = Image.open(FIRE_IMG_PATH).convert("RGB")
    w, h = img.size
    total_pixels = w * h

    if len(bits) > total_pixels:
        raise ValueError("Secret too long to hide in PIC OF THE FIRE image")

    pixels = img.load()
    i = 0

    for y in range(h):
        for x in range(w):
            if i >= len(bits):
                break
            r, g, b = pixels[x, y]
            r = (r & 0xFE) | int(bits[i])  # γράφουμε στο LSB του red
            pixels[x, y] = (r, g, b)
            i += 1
        if i >= len(bits):
            break

    os.makedirs(output_dir, exist_ok=True)
    out_name = f"pledge_{thr_address}_fire_stego.png"
    out_path = os.path.join(output_dir, out_name)
    img.save(out_path, "PNG")
    return out_path


def decode_seed_from_image(path: str) -> dict:
    """
    Utility για recovery: διαβάζει το stego PNG και γυρνά dict {thr_address, send_seed}.
    """
    img = Image.open(path).convert("RGB")
    w, h = img.size
    pixels = img.load()

    bits = []
    for y in range(h):
        for x in range(w):
            r, g, b = pixels[x, y]
            bits.append(str(r & 1))

    data_bytes = bytearray()
    for i in range(0, len(bits), 8):
        byte = int("".join(bits[i:i+8]), 2)
        if byte == 0:
            break
        data_bytes.append(byte)

    decoded = data_bytes.decode("utf-8")
    return json.loads(decoded)


# ───────────── AES helpers ───────────── #

def _get_aes_key() -> bytes:
    """
    THRONOS_PDF_AES_KEY από env → SHA256 → 32 bytes.
    Αν λείπει, χρησιμοποιεί 32 μηδενικά (όχι ιδανικό, αλλά σταθερό).
    """
    secret = os.getenv("THRONOS_PDF_AES_KEY", "")
    if not secret:
        return b"\x00" * 32
    return hashlib.sha256(secret.encode("utf-8")).digest()


def _encrypt_payload(payload: dict) -> str:
    raw = json.dumps(payload, sort_keys=True).encode("utf-8")
    key = _get_aes_key()

    cipher = AES.new(key, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(raw)

    blob = cipher.nonce + tag + ciphertext
    return base64.b64encode(blob).decode("ascii")


def _wrap_text(text: str, width: int):
    words = text.split()
    line = ""
    for w in words:
        if len(line) + len(w) + 1 <= width:
            line += (" " + w) if line else w
        else:
            yield line
            line = w
    if line:
        yield line


# ───────────── main PDF creator ───────────── #

def create_secure_pdf_contract(
    btc_address: str,
    pledge_text: str,
    thr_address: str,
    pledge_hash: str,
    height: int,
    send_seed: str,
    output_dir: str = None,
    node_label: str = "CPE_GATEWAY",
) -> str:
    """
    Φτιάχνει πλήρες pledge PDF:
      - header με BTC/THR/pledge
      - encrypted payload (AES/EAX/base64)
      - QR με node + THR + height
      - stego εικόνα φωτιάς με κρυμμένο send_seed
    Επιστρέφει ΜΟΝΟ το όνομα του PDF (π.χ. pledge_THR1234.pdf)
    """
    if output_dir is None:
        output_dir = _get_default_contracts_dir()

    os.makedirs(output_dir, exist_ok=True)

    # 1) Stego εικόνα
    stego_path = _embed_seed_in_fire_image(thr_address, send_seed, output_dir)

    # 2) Encrypted payload για απόδειξη
    payload = {
        "btc_address": btc_address,
        "thr_address": thr_address,
        "pledge_text": pledge_text,
        "pledge_hash": pledge_hash,
        "height": int(height),
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime()),
        "node": node_label,
    }
    encrypted_b64 = _encrypt_payload(payload)

    # 3) QR data
    qr_data = json.dumps(
        {
            "node": node_label,
            "thr_address": thr_address,
            "height": int(height),
        },
        sort_keys=True,
    )

    qr_img = qrcode.make(qr_data)
    qr_buf = BytesIO()
    qr_img.save(qr_buf, format="PNG")
    qr_bytes = qr_buf.getvalue()

    # 4) PDF
    pdf_name = f"pledge_{thr_address}.pdf"
    pdf_path = os.path.join(output_dir, pdf_name)

    c = canvas.Canvas(pdf_path, pagesize=A4)
    width, height_page = A4

    c.setFont("Helvetica-Bold", 16)
    c.drawString(1 * inch, height_page - 1 * inch, "THRONOS PLEDGE CONTRACT")

    c.setFont("Helvetica", 11)
    c.drawString(1 * inch, height_page - 1.4 * inch, f"BTC Address: {btc_address}")
    c.drawString(1 * inch, height_page - 1.7 * inch, f"THR Address: {thr_address}")
    c.drawString(1 * inch, height_page - 2.0 * inch, f"Pledge Hash: {pledge_hash}")
    c.drawString(1 * inch, height_page - 2.3 * inch, f"Node: {node_label}")
    c.drawString(1 * inch, height_page - 2.6 * inch, f"Block Height at Pledge: {height}")

    # Pledge text
    text_obj = c.beginText(1 * inch, height_page - 3.1 * inch)
    text_obj.setFont("Helvetica-Oblique", 11)
    for line in _wrap_text(pledge_text, 90):
        text_obj.textLine(line)
    c.drawText(text_obj)

    # Encrypted payload
    y_enc = height_page - 4.0 * inch
    c.setFont("Helvetica-Bold", 11)
    c.drawString(1 * inch, y_enc, "Encrypted (AES/EAX/base64) payload:")
    c.setFont("Helvetica", 8)

    for line in _wrap_text(encrypted_b64, 100):
        y_enc -= 10
        c.drawString(1 * inch, y_enc, line)

    y_enc -= 20
    c.setFont("Helvetica-Oblique", 9)
    c.drawString(
        1 * inch,
        y_enc,
        "A hidden seed is embedded inside the fire symbol image. "
        "Keep this PDF safe together with your personal phrase to recover your THR send secret.",
    )

    # QR + stego image
    qr_x = 1 * inch
    qr_y = 0.8 * inch
    c.drawInlineImage(qr_bytes, qr_x, qr_y, 2.0 * inch, 2.0 * inch)

    c.drawInlineImage(stego_path, 3.5 * inch, qr_y, 3.0 * inch, 3.0 * inch)

    c.showPage()
    c.save()

    return pdf_name
