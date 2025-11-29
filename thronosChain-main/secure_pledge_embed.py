import os
import json
import base64
import hashlib
import qrcode
import time
from PIL import Image
from fpdf import FPDF
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

# Configuration
CONTRACTS_DIR = "static/contracts"
SECRET_KEY = hashlib.sha256(b"thronos_super_secret_key").digest()[:16]  # 128-bit AES key
os.makedirs(CONTRACTS_DIR, exist_ok=True)

def encrypt_text_aes(text, key):
    cipher = AES.new(key, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(text.encode())
    return base64.b64encode(cipher.nonce + tag + ciphertext).decode()

def generate_qr_code(data, output_path):
    qr = qrcode.make(data)
    qr.save(output_path)

def embed_hash_in_image(image_path, hash_data, output_path):
    img = Image.open(image_path).convert("RGB")
    pixels = img.load()
    binary_hash = ''.join(format(ord(c), '08b') for c in hash_data)
    idx = 0
    for y in range(img.height):
        for x in range(img.width):
            if idx >= len(binary_hash):
                break
            r, g, b = pixels[x, y]
            r = (r & ~1) | int(binary_hash[idx])
            pixels[x, y] = (r, g, b)
            idx += 1
        if idx >= len(binary_hash):
            break
    img.save(output_path)

def create_secure_pdf_contract(btc_address, pledge_text, thr_address, pledge_hash, height):
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime())
    qr_data = json.dumps({
        "thr": thr_address,
        "height": height,
        "hash": pledge_hash
    })
    
    enc_pledge = encrypt_text_aes(pledge_text, SECRET_KEY)
    
    qr_path = os.path.join(CONTRACTS_DIR, f"qr_{thr_address}.png")
    qr_txt = os.path.join(CONTRACTS_DIR, f"stego_{thr_address}.png")
    base_img = os.path.join("assets", "phantom_base.png")  # provide a base image
    
    generate_qr_code(qr_data, qr_path)
    embed_hash_in_image(base_img, pledge_hash, qr_txt)

    pdf_name = f"pledge_{thr_address}.pdf"
    out = os.path.join(CONTRACTS_DIR, pdf_name)
    
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Courier", size=12)
    pdf.multi_cell(0, 10, f"BTC Address: {btc_address}\nPledge: {pledge_text}\nEncrypted: {enc_pledge}\nTHR Address: {thr_address}\nTime: {timestamp}")
    pdf.image(qr_path, x=10, y=pdf.get_y()+10, w=60)
    pdf.image(qr_txt, x=80, y=pdf.get_y(), w=100)
    pdf.output(out)

    return pdf_name

# Example usage:
if __name__ == "__main__":
    btc = "148t6A1xesYtCkXteMktjyTD7ojDWFikPY"
    pledge = "I pledge to the fire that never dies."
    addr = "THR1764279086647"
    hashv = hashlib.sha256((btc + pledge).encode()).hexdigest()
    create_secure_pdf_contract(btc, pledge, addr, hashv, 0)
