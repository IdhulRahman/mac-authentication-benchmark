import socket
import time
import hmac
import hashlib
import os
import csv
from Crypto.Hash import RIPEMD160
from Crypto.Hash import CMAC
from Crypto.Cipher import AES

# Konfigurasi
HOST = '192.168.1.19' # Ganti dengan alamat server yang sesuai
PORT = 5000 
KEY = b'0123456789ABCDEF0123456789ABCDEF' # Kunci untuk HMAC dan AES-CMAC
CSV_FILENAME = 'mac_benchmark_log.csv'

algorithms_list = ['HMAC-SHA256', 'RIPEMD-160', 'AES-CMAC'] # Daftar algoritma yang didukung

# Fungsi generate MAC
def compute_mac(data, algo):
    if algo == 'HMAC-SHA256':
        return hmac.new(KEY, data, hashlib.sha256).digest()  # 256-bit
    elif algo == 'RIPEMD-160':
        h = RIPEMD160.new()
        h.update(data)
        digest = h.digest() # 160-bit
        return digest + b'\x00' * (32 - len(digest))  # Pad to 256-bit
    elif algo == 'AES-CMAC':
        c = CMAC.new(KEY, ciphermod=AES)
        c.update(data)
        return c.digest()  # 128-bit (default)
    else:
        raise ValueError(f"Unknown algorithm: {algo}")

# Inisialisasi file CSV (buat header jika belum ada)
def init_csv_log():
    if not os.path.exists(CSV_FILENAME):
        with open(CSV_FILENAME, mode='w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow([
                'Algorithm', 'Sample_Index', 'Plaintext_Size_Bytes',
                'MAC_Hex', 'Computation_Delay_ms', 'Communication_Delay_ms'
            ]) # Header untuk CSV

# Simpan satu baris log
def log_to_csv(algo, idx, size, mac_hex, comp_ms, comm_ms):
    with open(CSV_FILENAME, mode='a', newline='') as f:
        writer = csv.writer(f)
        writer.writerow([
            algo, idx, size, mac_hex, f"{comp_ms:.6f}", f"{comm_ms:.6f}"
        ]) # Simpan log ke CSV

# Fungsi pilih algoritma
def select_algorithm():
    print("Pilih algoritma:")
    for idx, algo in enumerate(algorithms_list, 1):
        print(f"{idx}. {algo}") # Tampilkan daftar algoritma
    
    while True:
        try:
            choice = int(input("Masukkan nomor pilihan: "))
            if 1 <= choice <= len(algorithms_list):
                return algorithms_list[choice - 1]
            else:
                print("Pilihan tidak valid.")
        except ValueError:
            print("Input harus angka.")

# Fungsi input jumlah sample
def get_sample_count():
    while True:
        try:
            count = int(input("Masukkan jumlah sample yang ingin dikirim: ")) 
            if count > 0:
                return count
            else:
                print("Jumlah sample harus lebih dari 0.")
        except ValueError:
            print("Input harus berupa angka.")

# Fungsi input ukuran plaintext
def get_plaintext_size():
    while True:
        try:
            size_kb = int(input("Masukkan ukuran plaintext (KB): "))
            if size_kb > 0:
                return size_kb * 1024  # Konversi ke byte
            else:
                print("Ukuran harus lebih dari 0 KB.")
        except ValueError:
            print("Input harus berupa angka.")

# Fungsi utama loop client
def main_loop():
    init_csv_log()

    while True:
        selected_algo = select_algorithm()
        samples_per_algorithm = get_sample_count() 
        plaintext_size = get_plaintext_size()

        print(f"\nMenjalankan pengujian dengan algoritma: {selected_algo}")
        print(f"Jumlah sample: {samples_per_algorithm}")
        print(f"Ukuran plaintext: {plaintext_size // 1024} KB\n")

        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.connect((HOST, PORT))

                # Kirim algoritma
                algo_bytes = selected_algo.encode()
                s.sendall(len(algo_bytes).to_bytes(1, 'big') + algo_bytes)

                for i in range(samples_per_algorithm):
                    msg = os.urandom(plaintext_size)

                    # Komputasi MAC
                    start_comp = time.perf_counter()
                    mac = compute_mac(msg, selected_algo)
                    end_comp = time.perf_counter()
                    comp_delay = (end_comp - start_comp) * 1000  # ms

                    # Kirim data
                    start_comm = time.perf_counter() # Hitung waktu komunikasi
                    s.sendall(len(msg).to_bytes(4, 'big') + msg + mac) # Kirim panjang data, plaintext, dan MAC
                    end_comm = time.perf_counter() # Hitung waktu komunikasi
                    comm_delay = (end_comm - start_comm) * 1000  # ms

                    # Terima ACK dari server
                    ack = s.recv(1) # Terima ACK
                    ack_status = "VALID" if ack == b'\x01' else "INVALID" # Status ACK

                    # Log dan tampilkan
                    print(f"Sample {i+1}/{samples_per_algorithm}")
                    print(f"  - Plaintext (hex): {msg.hex()[:64]}...")
                    print(f"  - MAC (hex):       {mac.hex()}")
                    print(f"  - Comp Delay:      {comp_delay:.3f} ms")
                    print(f"  - Comm Delay:      {comm_delay:.3f} ms")
                    print(f"  - ACK Status:      {ack_status}\n")

                    log_to_csv(
                        selected_algo, i+1, len(msg),
                        mac.hex(), comp_delay, comm_delay
                    )

            print("\nSesi pengujian selesai.\n")

        except Exception as e:
            print(f"Terjadi error: {e}\n")

        ulang = input("Ingin melakukan pengujian lagi? (y/n): ").lower()
        if ulang != 'y':
            print("Program selesai.")
            break

# Eksekusi
if __name__ == "__main__":
    main_loop()
