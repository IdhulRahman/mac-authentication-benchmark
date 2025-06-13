import socket
import hmac
import hashlib
import time
import csv
from datetime import datetime
from Crypto.Hash import RIPEMD160
from Crypto.Hash import CMAC
from Crypto.Cipher import AES
import os

# Konfigurasi
HOST = '127.0.0.1' # Ganti dengan alamat server yang sesuai
PORT = 5000
KEY = b'0123456789ABCDEF0123456789ABCDEF' # Kunci untuk HMAC dan AES-CMAC
CSV_LOG = "log_validasi_server.csv" # Nama file log CSV

# Panjang MAC untuk tiap algoritma
mac_lengths = {
    "HMAC-SHA256": 32, # Panjang output HMAC-SHA256
    "RIPEMD-160": 32, # Panjang output RIPEMD-160
    "AES-CMAC": 16 # Panjang output AES-CMAC
}

# Fungsi generate MAC
def generate_mac(data, algo):
    if algo == "HMAC-SHA256":
        return hmac.new(KEY, data, hashlib.sha256).digest() # HMAC dengan SHA-256
    elif algo == "RIPEMD-160":
        h = RIPEMD160.new()
        h.update(data)
        digest = h.digest()
        return digest + b'\x00' * (32 - len(digest))  # pad to 256-bit
    elif algo == "AES-CMAC":
        cobj = CMAC.new(KEY, ciphermod=AES)
        cobj.update(data)
        return cobj.digest() # AES-CMAC
    else:
        raise ValueError("Algoritma tidak dikenali")

# Pilih mode output
def select_mode():
    print("Pilih mode output:")
    print("1. Tampilkan seluruh message (verbose)")
    print("2. Hanya tampilkan hasil ringkasan (summary)")
    while True:
        try:
            choice = int(input("Masukkan pilihan: "))
            if choice in (1, 2):
                return choice
            else:
                print("Pilihan tidak valid.")
        except ValueError:
            print("Input harus berupa angka.")

# Fungsi robust receive
def recvall(conn, length):
    data = b""
    while len(data) < length:
        more = conn.recv(length - len(data))
        if not more:
            return data
        data += more
    return data

# Inisialisasi file CSV (header jika belum ada)
def init_csv():
    if not os.path.exists(CSV_LOG):
        with open(CSV_LOG, mode='w', newline='') as file:
            writer = csv.writer(file)
            writer.writerow([
                "Sample ID", "Data Length (bytes)", "MAC Received",
                "MAC Expected", "Status", "Comp Delay (ms)", "Timestamp"
            ])

# Tulis log ke CSV
def log_to_csv(sample_id, data_len, mac_recv, mac_exp, status, delay):
    with open(CSV_LOG, mode='a', newline='') as file:
        writer = csv.writer(file)
        writer.writerow([
            sample_id,
            data_len,
            mac_recv.hex(),
            mac_exp.hex(),
            "VALID" if status else "INVALID",
            f"{delay:.3f}",
            datetime.now().isoformat()
        ])

# Fungsi main server
init_csv()
mode = select_mode()

while True:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
        server_socket.bind((HOST, PORT))
        server_socket.listen()
        print("\nServer is listening...")
        conn, addr = server_socket.accept()

        with conn:
            print(f"Connected by {addr}")

            # Terima algoritma
            algo_len = int.from_bytes(conn.recv(1), 'big')
            algorithm = conn.recv(algo_len).decode().strip()

            if algorithm not in mac_lengths:
                print(f"Algoritma tidak dikenali: {algorithm}")
                continue

            print(f"Algorithm selected: {algorithm}")
            mac_len = mac_lengths[algorithm]

            total_samples = 0
            valid_count = 0
            invalid_count = 0
            total_comp_time = 0

            last_data = b""
            last_mac_received = b""
            last_mac_expected = b""
            last_valid = False

            while True:
                header = conn.recv(4)
                if not header:
                    break

                data_len = int.from_bytes(header, 'big')
                data = recvall(conn, data_len)
                mac = recvall(conn, mac_len)

                if len(data) != data_len or len(mac) != mac_len:
                    print("Data tidak lengkap, koneksi terputus.")
                    break

                # Komputasi dan validasi
                start = time.perf_counter()
                expected_mac = generate_mac(data, algorithm)
                end = time.perf_counter()
                comp_delay = (end - start) * 1000  # ms

                valid = hmac.compare_digest(mac, expected_mac)

                # Kirim ACK
                conn.sendall(b'\x01' if valid else b'\x00')

                # Statistik
                total_samples += 1
                total_comp_time += comp_delay
                valid_count += valid
                invalid_count += not valid

                # Simpan sample terakhir
                last_data = data
                last_mac_received = mac
                last_mac_expected = expected_mac
                last_valid = valid

                # Log ke CSV
                log_to_csv(total_samples, len(data), mac, expected_mac, valid, comp_delay)

                # Output
                if mode == 1:
                    print(f"Sample {total_samples}")
                    print(f"  - Plaintext (hex): {data.hex()[:64]}...")
                    print(f"  - Received MAC:    {mac.hex()}")
                    print(f"  - Expected MAC:    {expected_mac.hex()}")
                    print(f"  - Status:          {'VALID' if valid else 'INVALID'}")
                    print(f"  - Comp Delay:      {comp_delay:.3f} ms\n")

            # Ringkasan
            print("\n--- SUMMARY ---")
            print(f"Total sample received: {total_samples}")
            print(f"Valid MAC: {valid_count}")
            print(f"Invalid MAC: {invalid_count}")
            if total_samples > 0:
                avg_comp_time = total_comp_time / total_samples
                print(f"Average computation delay: {avg_comp_time:.3f} ms")
            print("--- END ---\n")

            # Sample terakhir
            if mode == 2 and last_data:
                print("Contoh sample terakhir:")
                print(f"  - Plaintext (hex): {last_data.hex()[:64]}...")
                print(f"  - Received MAC:    {last_mac_received.hex()}")
                print(f"  - Expected MAC:    {last_mac_expected.hex()}")
                print(f"  - Status:          {'VALID' if last_valid else 'INVALID'}\n")
