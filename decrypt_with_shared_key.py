import os
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

def load_key_from_pem(file_path):
    with open(file_path, 'rb') as f:
        return serialization.load_pem_private_key(f.read(), password=None)

def load_public_key(file_path):
    with open(file_path, 'rb') as f:
        return serialization.load_pem_public_key(f.read())

def derive_shared_key(private_key, peer_public_key):
    shared_secret = private_key.exchange(ec.ECDH(), peer_public_key)
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'qkd-folder-encryption'
    ).derive(shared_secret)

def decrypt_file(file_path, output_folder, output_name, key):
    with open(file_path, 'rb') as f:
        data = f.read()
    iv = data[:16]
    encrypted = data[16:]

    cipher = Cipher(algorithms.AES(key), modes.CFB(iv))
    decryptor = cipher.decryptor()
    decrypted = decryptor.update(encrypted) + decryptor.finalize()

    with open(os.path.join(output_folder, output_name), 'wb') as out_file:
        out_file.write(decrypted)
    print(f"✅ Decrypted: {output_name}")

# Setup paths
encrypted_folder = "encrypted_files"
output_folder = "decrypted_files"
os.makedirs(output_folder, exist_ok=True)

# Load keys
bob_private_key = load_key_from_pem("bob_private.pem")
alice_public_key = load_public_key("alice_public.pem")
shared_key = derive_shared_key(bob_private_key, alice_public_key)

# Decrypt all files in the encrypted folder
for i, filename in enumerate(os.listdir(encrypted_folder), start=1):
    if filename.endswith(".enc"):
        input_path = os.path.join(encrypted_folder, filename)
        output_name = f"image{i}.jpg"  # name them image1.jpg, image2.jpg, ...
        decrypt_file(input_path, output_folder, output_name, shared_key)

print("🎉 All files decrypted.")
