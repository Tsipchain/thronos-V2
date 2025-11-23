
from PIL import Image
import json

def decode_payload_from_image(image_path):
    img = Image.open(image_path).convert("RGB")
    bits = ""
    for pixel in img.getdata():
        for color in pixel[:3]:  # Only RGB
            bits += str(color & 1)
    bytes_list = [bits[i:i+8] for i in range(0, len(bits), 8)]
    decoded_chars = []
    for byte in bytes_list:
        if byte == "00000000":
            break
        decoded_chars.append(chr(int(byte, 2)))
    payload_json = ''.join(decoded_chars)
    try:
        payload = json.loads(payload_json)
        print("✔️ Payload:", json.dumps(payload, indent=2))
    except:
        print("❌ Failed to decode.")
        print(payload_json)

if __name__ == "__main__":
    import sys
    decode_payload_from_image(sys.argv[1])
