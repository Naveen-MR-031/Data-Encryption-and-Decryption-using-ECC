import os
import time
import matplotlib.pyplot as plt
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

# Lists to store metrics
encryption_times = []
file_sizes = []

# Generate ECC key pair
def generate_ecc_key_pair():
    private_key = ec.generate_private_key(ec.SECP384R1())
    public_key = private_key.public_key()
    return private_key, public_key

# Derive AES key from ECC shared secret
def derive_key(private_key, peer_public_key):
    shared_secret = private_key.exchange(ec.ECDH(), peer_public_key)
    derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'qkd-folder-encryption',
    ).derive(shared_secret)
    return derived_key

# Encrypt a file with AES using derived key
def encrypt_file(file_path, key, output_folder, file_counter):
    start_time = time.time()

    with open(file_path, 'rb') as f:
        data = f.read()

    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv))
    encryptor = cipher.encryptor()
    encrypted_data = iv + encryptor.update(data) + encryptor.finalize()

    output_filename = f"image{file_counter}.enc"
    output_path = os.path.join(output_folder, output_filename)
    with open(output_path, 'wb') as f:
        f.write(encrypted_data)

    end_time = time.time()
    duration = end_time - start_time

    encryption_times.append((file_counter, duration))
    file_sizes.append((file_counter, len(data), len(encrypted_data)))

    print(f"Encrypted {file_counter}: {output_filename} in {duration:.4f} seconds")

# Save ECC keys to PEM files
def save_keys(alice_pub, bob_pub, bob_priv):
    for name, key in [("alice_public.pem", alice_pub),
                      ("bob_public.pem", bob_pub),
                      ("bob_private.pem", bob_priv)]:
        pem = key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ) if "public" in name else key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        )
        with open(name, 'wb') as f:
            f.write(pem)

# Set folders
input_folder = "files_to_encrypt"
output_folder = "encrypted_files"
os.makedirs(output_folder, exist_ok=True)

# Generate ECC keys and derive shared key
alice_priv, alice_pub = generate_ecc_key_pair()
bob_priv, bob_pub = generate_ecc_key_pair()
shared_key = derive_key(alice_priv, bob_pub)

# Encrypt all files in folder
file_counter = 1
for filename in os.listdir(input_folder):
    file_path = os.path.join(input_folder, filename)
    if os.path.isfile(file_path):
        encrypt_file(file_path, shared_key, output_folder, file_counter)
        file_counter += 1

# Save ECC keys
save_keys(alice_pub, bob_pub, bob_priv)

# Plot encryption time per file
x = [item[0] for item in encryption_times]
y = [item[1] for item in encryption_times]

plt.figure(figsize=(10, 5))
plt.plot(x, y, marker='o')
plt.xlabel("File Number")
plt.ylabel("Encryption Time (seconds)")
plt.title("Encryption Time per File")
plt.grid(True)
plt.savefig("encryption_time_graph.png")
plt.show()

# Plot file size comparison
file_nums = [item[0] for item in file_sizes]
original_sizes = [item[1] for item in file_sizes]
encrypted_sizes = [item[2] for item in file_sizes]

plt.figure(figsize=(10, 5))
plt.plot(file_nums, original_sizes, label="Original Size", marker='o')
plt.plot(file_nums, encrypted_sizes, label="Encrypted Size", marker='x')
plt.xlabel("File Number")
plt.ylabel("Size (bytes)")
plt.title("Original vs Encrypted File Sizes")
plt.legend()
plt.grid(True)
plt.savefig("file_size_comparison.png")
plt.show()

print("✅ All images encrypted and graphs saved as PNG files.")
