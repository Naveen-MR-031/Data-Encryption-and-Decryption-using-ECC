# import os
# from cryptography.hazmat.primitives.asymmetric import ec
# from cryptography.hazmat.primitives import hashes
# from cryptography.hazmat.primitives.kdf.hkdf import HKDF
# from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
# from cryptography.hazmat.primitives import serialization

# # Generate ECC key pair (same for all folders)
# def generate_ecc_key_pair():
#     private_key = ec.generate_private_key(ec.SECP384R1())
#     public_key = private_key.public_key()
#     return private_key, public_key

# # Derive shared key using the ECC keys (same for all folders)
# def derive_key(private_key, peer_public_key):
#     shared_secret = private_key.exchange(ec.ECDH(), peer_public_key)
#     derived_key = HKDF(
#         algorithm=hashes.SHA256(),
#         length=32,
#         salt=None,
#         info=b'qkd-folder-encryption',
#     ).derive(shared_secret)
#     return derived_key

# # Encrypt a single file using the shared key
# def encrypt_file(input_path, output_path, key):
#     with open(input_path, 'rb') as f:
#         data = f.read()

#     iv = os.urandom(16)
#     cipher = Cipher(algorithms.AES(key), modes.CFB(iv))
#     encryptor = cipher.encryptor()
#     encrypted_data = iv + encryptor.update(data) + encryptor.finalize()

#     os.makedirs(os.path.dirname(output_path), exist_ok=True)
#     with open(output_path, 'wb') as f:
#         f.write(encrypted_data)

# # Encrypt all files inside a folder
# def encrypt_folder(subfolder_path, output_root, shared_key):
#     folder_name = os.path.basename(subfolder_path)
#     output_folder = os.path.join(output_root, folder_name + "_encrypted")
#     os.makedirs(output_folder, exist_ok=True)

#     for file_name in os.listdir(subfolder_path):
#         input_file = os.path.join(subfolder_path, file_name)
#         if os.path.isfile(input_file):
#             name_wo_ext = os.path.splitext(file_name)[0]
#             output_file = os.path.join(output_folder, name_wo_ext + ".enc")
#             encrypt_file(input_file, output_file, shared_key)
#             print(f"  ✅ Encrypted: {file_name} → {name_wo_ext}.enc")

# # Save public and private keys as PEM files
# def save_keys(alice_priv, alice_pub, bob_priv, bob_pub):
#     # Save Alice's keys
#     with open("alice_private.pem", "wb") as f:
#         f.write(alice_priv.private_bytes(
#             encoding=serialization.Encoding.PEM,
#             format=serialization.PrivateFormat.TraditionalOpenSSL,
#             encryption_algorithm=serialization.NoEncryption()
#         ))
#     with open("alice_public.pem", "wb") as f:
#         f.write(alice_pub.public_bytes(
#             encoding=serialization.Encoding.PEM,
#             format=serialization.PublicFormat.SubjectPublicKeyInfo
#         ))

#     # Save Bob's keys
#     with open("bob_private.pem", "wb") as f:
#         f.write(bob_priv.private_bytes(
#             encoding=serialization.Encoding.PEM,
#             format=serialization.PrivateFormat.TraditionalOpenSSL,
#             encryption_algorithm=serialization.NoEncryption()
#         ))
#     with open("bob_public.pem", "wb") as f:
#         f.write(bob_pub.public_bytes(
#             encoding=serialization.Encoding.PEM,
#             format=serialization.PublicFormat.SubjectPublicKeyInfo
#         ))

# # === MAIN ===
# input_root = "files_to_encrypt"  # Parent folder containing subfolders with images
# output_root = "encrypted_output"  # Folder where encrypted files will be saved
# os.makedirs(output_root, exist_ok=True)

# # Generate ECC keys for the whole encryption
# alice_priv, alice_pub = generate_ecc_key_pair()
# bob_priv, bob_pub = generate_ecc_key_pair()

# # Save the keys as PEM files
# save_keys(alice_priv, alice_pub, bob_priv, bob_pub)
# print("🔑 ECC keys saved as PEM files (alice_private.pem, alice_public.pem, bob_private.pem, bob_public.pem).")

# # Use Alice's private key and Bob's public key to derive the shared key
# shared_key = derive_key(alice_priv, bob_pub)

# # Show the quantum key in terminal (the shared key to be used for decryption)
# print(f"\n🔐 Quantum Key for Decryption (share this with receiver):\n{shared_key.hex()}")
# print("------------------------------------------------------------")

# # Encrypt all folders with the same shared key
# for folder in os.listdir(input_root):
#     subfolder_path = os.path.join(input_root, folder)
#     if os.path.isdir(subfolder_path):
#         encrypt_folder(subfolder_path, output_root, shared_key)

# print("\n🎉 All folders encrypted with the same shared quantum key.")
import os
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import serialization

# Generate ECC key pair (same for all folders and files)
def generate_ecc_key_pair():
    private_key = ec.generate_private_key(ec.SECP384R1())
    public_key = private_key.public_key()
    return private_key, public_key

# Derive shared key using ECC keys
def derive_key(private_key, peer_public_key):
    shared_secret = private_key.exchange(ec.ECDH(), peer_public_key)
    derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'qkd-folder-encryption',
    ).derive(shared_secret)
    return derived_key

# Encrypt a single file using the shared key
def encrypt_file(input_path, output_path, key):
    with open(input_path, 'rb') as f:
        data = f.read()

    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv))
    encryptor = cipher.encryptor()
    encrypted_data = iv + encryptor.update(data) + encryptor.finalize()

    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, 'wb') as f:
        f.write(encrypted_data)

# Encrypt all files inside a folder
def encrypt_folder(subfolder_path, output_root, shared_key):
    folder_name = os.path.basename(subfolder_path)
    output_folder = os.path.join(output_root, folder_name + "_encrypted")
    os.makedirs(output_folder, exist_ok=True)

    for file_name in os.listdir(subfolder_path):
        input_file = os.path.join(subfolder_path, file_name)
        if os.path.isfile(input_file):
            name_wo_ext = os.path.splitext(file_name)[0]
            output_file = os.path.join(output_folder, name_wo_ext + ".enc")
            encrypt_file(input_file, output_file, shared_key)
            print(f"  ✅ Encrypted (Folder): {file_name} → {name_wo_ext}.enc")

# Encrypt a single file directly (outside folder)
def encrypt_single_file(file_path, output_root, shared_key):
    file_name = os.path.basename(file_path)
    name_wo_ext = os.path.splitext(file_name)[0]
    output_file = os.path.join(output_root, name_wo_ext + ".enc")
    encrypt_file(file_path, output_file, shared_key)
    print(f"  ✅ Encrypted (Single File): {file_name} → {name_wo_ext}.enc")

# Save public and private keys as PEM files
def save_keys(alice_priv, alice_pub, bob_priv, bob_pub):
    with open("alice_private.pem", "wb") as f:
        f.write(alice_priv.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ))
    with open("alice_public.pem", "wb") as f:
        f.write(alice_pub.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))

    with open("bob_private.pem", "wb") as f:
        f.write(bob_priv.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ))
    with open("bob_public.pem", "wb") as f:
        f.write(bob_pub.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))

# === MAIN ===
input_root = "files_to_encrypt"  # Parent folder containing files and folders
output_root = "encrypted_output"  # Folder where encrypted files will be saved
os.makedirs(output_root, exist_ok=True)

# Generate ECC keys
alice_priv, alice_pub = generate_ecc_key_pair()
bob_priv, bob_pub = generate_ecc_key_pair()

# Save the keys as PEM files
save_keys(alice_priv, alice_pub, bob_priv, bob_pub)
print("🔑 ECC keys saved as PEM files (alice_private.pem, alice_public.pem, bob_private.pem, bob_public.pem).")

# Derive shared key
shared_key = derive_key(alice_priv, bob_pub)

# Display shared key
print(f"\n🔐 Quantum Key for Decryption (share this with receiver):\n{shared_key.hex()}")
print("------------------------------------------------------------")

# Encrypt files and folders
for item in os.listdir(input_root):
    item_path = os.path.join(input_root, item)
    if os.path.isdir(item_path):
        encrypt_folder(item_path, output_root, shared_key)
    elif os.path.isfile(item_path):
        encrypt_single_file(item_path, output_root, shared_key)

print("\n🎉 All files and folders encrypted with the shared quantum key.")
