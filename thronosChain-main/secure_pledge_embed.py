# secure_pledge_embed.py
#
# Δημιουργεί:
#  - AES-encrypted pledge text
#  - QR PNG με THR + height + pledge_hash + node_id
#  - Stego PNG (LSB) πάνω στο PIC OF THE FIRE.png
#  - PDF συμβόλαιο που περιέχει όλα τα παραπάνω

import os
import json
import base64
import hashlib
import qrcode
import time
from PIL import Image
from fpdf import FPDF

# Χρησιμοποιούμε pycryptodomex (όχι το παλιό Crypto)
from Cryptodome.Cipher import AES
from Cryptodome.Random import get_random_bytes  # αν χρειαστεί στο μέλλον

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
STATIC_DIR = os.path.join(BASE_DIR, "static")
CONTRACTS_DIR = os.path.join(STATIC_DIR, "contracts")

os.makedirs(CONTRACTS_DIR, exist_ok=True)

# 128-bit AES key (παράδειγμα – μπορείς να το αλλάξεις / βάλεις από .env)
SECRET_KEY = hashlib.sha256(b"thronos_super_secret_key").digest()[:16]

def encrypt_text_aes(text: str, key: bytes) -> str:
    cipher = AES.new(key, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(text.encode("utf-8"))
    payload = cipher.nonce + tag + ciphertext
    return base64.b64encode(payload).decode("utf-8")

def generate_qr_code(data: str, output_path: str) -> None:
    qr = qrcode.make(data)
    qr.save(output_path)

def embed_hash_in_image(base_image_path: str, hash_data: str, output_path: str) -> None:
    """
    LSB steganography: κρύβει το hash στα LSB του κόκκινου καναλιού.
    """
    img = Image.open(base_image_path).convert("RGB")
    pixels = img.load()

    binary_hash = "".join(format(ord(c), "08b") for c in hash_data)
    idx = 0

    for y in range(img.height):
        for x in range(img.width):
            if idx >= len(binary_hash):
                break
            r, g, b = pixels[x, y]
            r = (r & ~1) | int(binary_hash[idx])  # αλλάζουμε μόνο το LSB του κόκκινου
            pixels[x, y] = (r, g, b)
            idx += 1
        if idx >= len(binary_hash):
            break

    img.save(output_path)

def create_secure_pdf_contract(
    btc_address: str,
    pledge_text: str,
    thr_address: str,
    pledge_hash: str,
    height: int,
) -> str:
    """
    Δημιουργεί:
      - QR PNG με THR + height + pledge_hash + node_id
      - Stego PNG πάνω στο PIC OF THE FIRE.png
      - PDF συμβόλαιο με τα παραπάνω
    Επιστρέφει το όνομα του PDF (π.χ. pledge_THR1234....pdf)
    """
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime())
    node_id = "CPE_GATEWAY"  # εδώ μπορείς να βάλεις όνομα κόμβου / WhisperNode

    qr_payload = {
        "thr": thr_address,
        "height": height,
        "hash": pledge_hash,
        "node": node_id,
    }
    qr_data = json.dumps(qr_payload)

    # AES encryption του pledge text
    enc_pledge = encrypt_text_aes(pledge_text, SECRET_KEY)

    # Paths για τα αρχεία εικόνας
    qr_path = os.path.join(CONTRACTS_DIR, f"qr_{thr_address}.png")
    stego_path = os.path.join(CONTRACTS_DIR, f"stego_{thr_address}.png")

    # Βάση εικόνας για stego: χρησιμοποιούμε το PIC OF THE FIRE.png στο root
    base_img = os.path.join(BASE_DIR, "PIC OF THE FIRE.png")

    generate_qr_code(qr_data, qr_path)
    embed_hash_in_image(base_img, pledge_hash, stego_path)

    # Όνομα PDF
    pdf_name = f"pledge_{thr_address}.pdf"
    pdf_path = os.path.join(CONTRACTS_DIR, pdf_name)

    # Δημιουργία PDF
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Courier", size=12)

    header = (
        f"THRONOS BLOCKCHAIN CONTRACT\n\n"
        f"BTC Address: {btc_address}\n"
        f"THR Address: {thr_address}\n"
        f"Node: {node_id}\n"
        f"Time: {timestamp}\n\n"
        f"Pledge:\n{pledge_text}\n\n"
        f"Encrypted (AES/EAX/base64):\n{enc_pledge}\n"
    )

    pdf.multi_cell(0, 6, header)

    # Τρέχουσα θέση και εισαγωγή εικόνων
    y = pdf.get_y() + 5
    pdf.image(qr_path,    x=10,  y=y, w=60)
    pdf.image(stego_path, x=80,  y=y, w=100)

    pdf.output(pdf_path)

    return pdf_name

# Local test
if __name__ == "__main__":
    btc = "148t6A1xesYtCkXteMktjyTD7ojDWFikPY"
    pledge = "I pledge to the fire that never dies."
    addr = "THR1764279086647"
    hashv = hashlib.sha256((btc + pledge).encode()).hexdigest()
    print("Creating test secure contract...")
    pdf_file = create_secure_pdf_contract(btc, pledge, addr, hashv, height=0)
    print("Created:", pdf_file)
