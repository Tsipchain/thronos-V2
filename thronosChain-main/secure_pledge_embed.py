import os
import io
import base64
import uuid
import hashlib
from datetime import datetime

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from PIL import Image
import qrcode

from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import A4
from reportlab.lib.utils import ImageReader

# Βασικά paths
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
# To “PIC OF THE FIRE.png” που χρησιμεύει σαν βάση stego
FIRE_BASE_PATH = os.path.join(BASE_DIR, "static", "PIC OF THE FIRE.png")


# ─────────────────────────────────────────────────────────
#  AES κρυπτογράφηση pledge
# ─────────────────────────────────────────────────────────
def encrypt_pledge_text(pledge_text: str, send_seed: str) -> str:
    """
    Κρυπτογραφεί το pledge με AES/EAX.
    Το κλειδί προκύπτει από sha256(send_seed).
    Επιστρέφει base64(nonce || tag || ciphertext).
    """
    key = hashlib.sha256(send_seed.encode("utf-8")).digest()
    cipher = AES.new(key, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(pledge_text.encode("utf-8"))

    blob = cipher.nonce + tag + ciphertext
    return base64.b64encode(blob).decode("ascii")


# ─────────────────────────────────────────────────────────
#  Stego: κρύβουμε το send_seed στα LSB του κόκκινου καναλιού
# ─────────────────────────────────────────────────────────
def embed_seed_in_fire_image(send_seed: str, output_dir: str) -> str:
    """
    Φορτώνει το PIC OF THE FIRE.png και κρύβει το send_seed
    στα LSB του κόκκινου καναλιού. Επιστρέφει το path του
    stego PNG (που θα μπει στο PDF).
    """
    if not os.path.exists(FIRE_BASE_PATH):
        raise FileNotFoundError(f"Base fire image not found: {FIRE_BASE_PATH}")

    img = Image.open(FIRE_BASE_PATH).convert("RGB")
    pixels = img.load()

    seed_bytes = send_seed.encode("utf-8")  # π.χ. 32 hex chars
    bits = "".join(f"{b:08b}" for b in seed_bytes)

    width, height = img.size
    total_pixels = width * height
    if len(bits) > total_pixels:
        raise ValueError("Seed too long to embed in fire image")

    # Γράφουμε bits στα LSB του red channel, σκανάροντας γραμμικά
    i = 0
    for y in range(height):
        for x in range(width):
            if i >= len(bits):
                break
            r, g, b = pixels[x, y]
            bit = int(bits[i])
            r = (r & ~1) | bit  # βάζουμε το bit στο LSB
            pixels[x, y] = (r, g, b)
            i += 1
        if i >= len(bits):
            break

    os.makedirs(output_dir, exist_ok=True)
    stego_name = f"fire_stego_{uuid.uuid4().hex}.png"
    stego_path = os.path.join(output_dir, stego_name)
    img.save(stego_path, format="PNG")
    return stego_path


# ─────────────────────────────────────────────────────────
#  Δημιουργία PDF συμβολαίου
# ─────────────────────────────────────────────────────────
def create_secure_pdf_contract(
    btc_address: str,
    pledge_text: str,
    thr_address: str,
    pledge_hash: str,
    height: int,
    send_seed: str,
    output_dir: str,
) -> str:
    """
    Δημιουργεί ένα secure PDF συμβόλαιο με:
    - βασικές πληροφορίες block/διευθύνσεων
    - AES/EAX κρυπτογραφημένο pledge (base64)
    - QR code με payload του pledge/block
    - stego fire image που κρύβει το send_seed

    Επιστρέφει ΜΟΝΟ το filename (όχι full path), π.χ.
    'pledge_<random>.pdf'
    """

    os.makedirs(output_dir, exist_ok=True)

    # Random filename για privacy
    pdf_name = f"pledge_{uuid.uuid4().hex}.pdf"
    pdf_path = os.path.join(output_dir, pdf_name)

    # 1) Κρυπτογραφημένο pledge
    encrypted_pledge_b64 = encrypt_pledge_text(pledge_text, send_seed)

    # 2) Stego image με send_seed
    stego_path = embed_seed_in_fire_image(send_seed, output_dir)

    # 3) QR payload
    qr_payload = {
        "btc_address": btc_address,
        "thr_address": thr_address,
        "pledge_hash": pledge_hash,
        "height": height,
    }
    qr_text = json_dumps_compact(qr_payload)

    qr_img = qrcode.make(qr_text)
    qr_buffer = io.BytesIO()
    qr_img.save(qr_buffer, format="PNG")
    qr_buffer.seek(0)
    qr_reader = ImageReader(qr_buffer)

    # 4) Δημιουργία PDF με reportlab
    c = canvas.Canvas(pdf_path, pagesize=A4)
    width, height_page = A4

    top_y = height_page - 40

    c.setFont("Helvetica-Bold", 14)
    c.drawString(40, top_y, "Thronos Chain - Pledge Contract")

    c.setFont("Helvetica", 10)
    c.drawString(40, top_y - 20, f"BTC Address (KYC): {btc_address}")
    c.drawString(40, top_y - 35, f"THR Address: {thr_address}")
    c.drawString(40, top_y - 50, f"Pledge Hash: {pledge_hash}")
    c.drawString(40, top_y - 65, f"Block Height (local): {height}")
    c.drawString(40, top_y - 80, f"Created: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}")

    # Pledge text (plain)
    c.setFont("Helvetica-Bold", 11)
    c.drawString(40, top_y - 110, "Pledge:")
    c.setFont("Helvetica", 10)
    text_obj = c.beginText(40, top_y - 125)
    for line in wrap_text(pledge_text, 90):
        text_obj.textLine(line)
    c.drawText(text_obj)

    # Encrypted pledge base64
    enc_y = top_y - 200
    c.setFont("Helvetica-Bold", 11)
    c.drawString(40, enc_y, "Encrypted (AES/EAX/base64):")
    c.setFont("Helvetica", 8)
    enc_text = c.beginText(40, enc_y - 15)
    for line in wrap_text(encrypted_pledge_b64, 90):
        enc_text.textLine(line)
    c.drawText(enc_text)

    # QR code αριστερά
    qr_size = 200
    c.drawImage(qr_reader, 40, 100, width=qr_size, height=qr_size, preserveAspectRatio=True, mask="auto")

    # Stego fire image δεξιά
    fire_reader = ImageReader(stego_path)
    c.drawImage(
        fire_reader,
        300,
        80,
        width=250,
        height=250,
        preserveAspectRatio=True,
        mask="auto",
    )

    c.showPage()
    c.save()

    return pdf_name


# ─────────────────────────────────────────────────────────
#  Helpers
# ─────────────────────────────────────────────────────────
def wrap_text(text: str, width: int):
    """
    Σπάει ένα string σε γραμμές max 'width' chars για το PDF.
    Πολύ απλό αστικό type wrap.
    """
    words = text.split()
    if not words:
        return []
    lines = []
    current = words[0]
    for w in words[1:]:
        if len(current) + 1 + len(w) <= width:
            current += " " + w
        else:
            lines.append(current)
            current = w
    lines.append(current)
    return lines


def json_dumps_compact(obj) -> str:
    import json
    return json.dumps(obj, separators=(",", ":"))
