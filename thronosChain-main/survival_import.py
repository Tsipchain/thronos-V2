import requests, time, json

PLEDGE_CHAIN = "pledge_chain.json"
SUBMIT_URL   = "https://thrchain.up.railway.app/submit_block"

def load_pledges():
    try:
        return json.load(open(PLEDGE_CHAIN))
    except:
        return []

def get_thr_address(btc_address):
    pledges = load_pledges()
    p = next((p for p in pledges if p["btc_address"]==btc_address), None)
    return p["thr_address"] if p else None

def start_worker():
    miner_btc = "3KUGVJ96T3JHuUrEHMeAvDKSo1zM9tD9nF"
    thr_addr  = get_thr_address(miner_btc)

    while True:
        payload = {
            "miner_btc_address": miner_btc,
            "thr_address":       thr_addr,       # από το pledge
            "referral":          None,
            "block_hash":        f"THR-survival-{int(time.time())}"
        }
        try:
            r = requests.post(SUBMIT_URL, json=payload, timeout=15)
            print("⇨", r.status_code, r.json())
        except Exception as e:
            print("✖️", e)
        time.sleep(60)

if __name__=="__main__":
    start_worker()


