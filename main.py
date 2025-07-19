import os
import time
import random
import matplotlib.pyplot as plt
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

# ---------------------- ECC Key Generation and Derivation ----------------------
def generate_ecc_key_pair():
    private_key = ec.generate_private_key(ec.SECP384R1())
    public_key = private_key.public_key()
    return private_key, public_key

def derive_key(private_key, peer_public_key):
    shared_secret = private_key.exchange(ec.ECDH(), peer_public_key)
    derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=16,  # 128-bit AES key
        salt=None,
        info=b'ecc-qkd-encryption',
    ).derive(shared_secret)
    return derived_key

# ---------------------- Simulate QKD (BB84 Protocol - Simplified) ----------------------
def simulate_qkd_key(length=128):
    key_bits = [random.randint(0, 1) for _ in range(length)]
    key_bytes = bytes(int("".join(map(str, key_bits[i:i+8])), 2) for i in range(0, length, 8))
    return key_bytes

# ---------------------- AES File Encryption ----------------------
def encrypt_file(input_path, key, output_path):
    with open(input_path, 'rb') as f:
        data = f.read()
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv))
    encryptor = cipher.encryptor()
    encrypted_data = iv + encryptor.update(data) + encryptor.finalize()
    with open(output_path, 'wb') as f:
        f.write(encrypted_data)

# ---------------------- Encrypt Files with Metrics ----------------------
def encrypt_files_with_metrics(input_folder, output_folder, key):
    files = []
    times = []
    sizes_orig = []
    sizes_enc = []

    for i, filename in enumerate(os.listdir(input_folder), start=1):
        input_path = os.path.join(input_folder, filename)
        output_filename = f'{i}'  # Changed to just the integer 1, 2, 3...
        output_path = os.path.join(output_folder, output_filename)

        if os.path.isfile(input_path):
            start = time.time()
            encrypt_file(input_path, key, output_path)
            end = time.time()

            files.append(filename)
            times.append(round(end - start, 6))
            sizes_orig.append(os.path.getsize(input_path))
            sizes_enc.append(os.path.getsize(output_path))
            print(f"✅ Encrypted '{filename}' ➜ '{output_filename}' in {times[-1]} seconds")

    return files, times, sizes_orig, sizes_enc


# ---------------------- Plot Performance Graph ----------------------
def plot_performance(files, sizes_orig, times):
    plt.figure(figsize=(10, 6))
    plt.plot(sizes_orig, times, marker='o', linestyle='-', color='teal')
    for i, txt in enumerate(files):
        plt.annotate(txt, (sizes_orig[i], times[i]), textcoords="offset points", xytext=(5, 5), ha='left')
    plt.title("File Encryption: Time vs File Size")
    plt.xlabel("Original File Size (bytes)")
    plt.ylabel("Encryption Time (seconds)")
    plt.grid(True)
    plt.tight_layout()
    plt.show()

# ---------------------- Main Program ----------------------
if __name__ == "__main__":
    input_folder = "files_to_encrypt"
    output_folder = "encrypted_files"
    os.makedirs(output_folder, exist_ok=True)

    print("🔐 Simulating Quantum Key Distribution (BB84)...")
    qkd_key = simulate_qkd_key()
    print(f"✅ Quantum Key (first 16 bytes): {qkd_key[:16].hex()}")

    print("🔐 Deriving ECC Key...")
    alice_priv, alice_pub = generate_ecc_key_pair()
    bob_priv, bob_pub = generate_ecc_key_pair()
    ecc_key = derive_key(alice_priv, bob_pub)
    print(f"🔐 Final AES Key: {(bytes(a ^ b for a, b in zip(ecc_key, qkd_key[:len(ecc_key)]))).hex()}")

    final_key = bytes(a ^ b for a, b in zip(ecc_key, qkd_key[:len(ecc_key)]))

    print(f"🚀 Encrypting files from '{input_folder}'...")
    files, times, sizes_orig, sizes_enc = encrypt_files_with_metrics(input_folder, output_folder, final_key)

    print("📈 Generating encryption performance graph...")
    plot_performance(files, sizes_orig, times)
