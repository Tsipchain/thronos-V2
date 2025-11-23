
import json
from datetime import datetime
from pathlib import Path
import sys

CHAIN_PATH = Path("phantom_tx_chain.json")
TX_LOG_PATH = Path("send_thr_log.json")

def load_chain():
    if CHAIN_PATH.exists():
        with open(CHAIN_PATH, "r") as f:
            return json.load(f)
    return []

def save_chain(chain):
    with open(CHAIN_PATH, "w") as f:
        json.dump(chain, f, indent=2)

def log_transaction(tx):
    logs = []
    if TX_LOG_PATH.exists():
        with open(TX_LOG_PATH, "r") as f:
            logs = json.load(f)
    logs.append(tx)
    with open(TX_LOG_PATH, "w") as f:
        json.dump(logs, f, indent=2)

def get_balance(address, chain):
    balance = 0.0
    for block in chain:
        if block.get("reward_to_address") == address:
            balance += float(block.get("reward", 0))
        if block.get("from") == address:
            balance -= float(block.get("amount", 0))
    return round(balance, 6)

def send_thr(from_addr, to_addr, amount):
    chain = load_chain()
    balance = get_balance(from_addr, chain)
    if balance < amount:
        print(f"Insufficient balance. Current: {balance}, Required: {amount}")
        return

    block = {
        "type": "transfer",
        "timestamp": datetime.utcnow().isoformat(),
        "from": from_addr,
        "to": to_addr,
        "amount": amount,
        "block_hash": f"THR_TX_{datetime.utcnow().timestamp()}"
    }
    chain.append(block)
    save_chain(chain)
    log_transaction(block)
    print(f"✅ Sent {amount} THR from {from_addr} to {to_addr}.")

if __name__ == "__main__":
    if len(sys.argv) != 4:
        print("Usage: python send_thr.py <from_address> <to_address> <amount>")
        sys.exit(1)
    send_thr(sys.argv[1], sys.argv[2], float(sys.argv[3]))
