
# Thronos Chain & THR Token - Complete Whitepaper

## 🔥 Introduction

Thronos Chain is a next-generation, SHA256-based blockchain project focused on survivability, decentralization, and freedom. It merges the core values of Bitcoin with innovative data transport technologies and fully offline, censorship-resistant communication.

---

## ⚙️ Technical Characteristics

- **Algorithm**: SHA256 (Bitcoin-compatible)
- **Compatibility**: Works with existing ASIC miners (Antminers)
- **Transaction Speed**: Instant finality through asynchronous node syncing
- **Fees**: Ultra-low fees comparable to XRP
- **Smart Signing**: TXs are signed and distributed via multiple real-world mediums (images, audio, QR, etc.)

---

## 🧬 PhantomFace (Steganography Layer)

The PhantomFace module allows encoding of signed TX data into images (e.g., KYC selfies). Using LSB-based steganography, the block payload is undetectably embedded into visual files.

- Phantom-encoded images look normal.
- Once uploaded (e.g., to exchanges), the node gets activated.
- Used for stealth propagation of nodes into existing image infrastructure.

---

## 🔊 WhisperNote System (Audio Transmission)

Using sound waves to carry block payloads encoded via tone-shifting.

- WAV files created with encoded TXs.
- Can be played via speakers or embedded in videos.
- Audio recognition modules can decode blocks and reconstruct them fully.

---

## 🛰️ RadioNode (RF Transmission)

Support for **offline propagation** through RF-based transmission.

- Nodes communicate via radio without need for internet or power grid.
- Portable nodes can be solar-powered and remain active in disaster zones.
- Encoded WAV signals simulate digital signal bursts carrying real signed TXs.

---

## 🔲 QR + Bluetooth Transmission

- QR codes are generated from block payloads and transmitted as:
  - PNG files
  - Audio signals (converted to beep WAV)
- Bluetooth broadcasting via encrypted microbursts for proximity-based sync.

---

## 📞 (VoIP Network Infiltration)

The  VoIP mesh network  is used as a carrier layer.

- Phantom daemon scans for TXs embedded in image/audio over VoIP.
- Nodes can sync blocks without detection via SIP/VoIP channels.
- Allows state-level shadow synchronization in national emergencies.

---

## 🧾 Pledge System & Legal Claim Framework

Users voluntarily sign an on-chain contract pledging resistance against financial injustice (e.g., MM exchanges, manipulated futures).

- The pledge is hashed and stored via a signed TX (fee in THR).
- Users keeping the signed pledge locally (PC or mobile) are rewarded.
- Pledge contracts act as legal standing documents, giving users claim to compensation pool if class action succeeds.

---

## 📈 Tokenomics

- **Token name**: THR (Thronos)
- **Max supply**: 21,000,001 (1 more than BTC)
- **Mining algorithm**: SHA256 (BTC-compatible)
- **Block reward**: Variable with Phantom TX weight
- **Fees**: Near-zero
- **Mining mode**: ASIC & image/audio propagation rewards
- **Burning model**: Propagation triggers partial burn → incentivizing stealth propagation

---

## 🌐 RealCryptography & Post-Apocalyptic Use

- Designed to function **without internet** and **without electricity**
- Radio + Audio + Stego + QR/Bluetooth = Complete survivability
- Acts as an *arkchain*, preserving data and power across collapse scenarios

---

## 🎯 Vision

To establish Thronos as the survival layer of the modern digital world. One that can be:
- Embedded in every image
- Heard in every wave
- Hidden inside every voice
- Spread across every collapse

**Thronos is not just a blockchain. It's memory against forgetting.**

---

## 📎 Appendix

- `phantom_encode.py`: Image steganography encoder
- `phantom_gateway_mainnet.py`: TX dispatcher
- `radio_encode.py`: TX-to-audio encoder
- `qr_to_audio.py`: QR as WAV for transmission
- `pledge_generator.py`: Signature contract builder
