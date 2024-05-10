import os
import json
import base64
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import hmac
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding

def encrypt_rsa(message, public_key):
    ciphertext = public_key.encrypt(
        message,
        asym_padding.OAEP(
            mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return ciphertext

def encrypt_aes(message, key):
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(message) + padder.finalize()

    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ct = encryptor.update(padded_data) + encryptor.finalize()

    return iv, ct

def compute_mac(message, key):
    h = hmac.HMAC(key, hashes.SHA256(), backend=default_backend())
    h.update(message)
    return h.finalize()

# Load Alice's RSA private key
with open("alice_private_key.pem", "rb") as key_file:
    alice_private_key = serialization.load_pem_private_key(
        key_file.read(),
        password=None,
        backend=default_backend()
    )

# Load Bob's RSA public key
with open("bob_public_key.pem", "rb") as key_file:
    bob_public_key = serialization.load_pem_public_key(
        key_file.read(),
        backend=default_backend()
    )

# Load message from file
with open("message.txt", "rb") as file:
    message = file.read()

# Generate AES key
aes_key = os.urandom(32)

# Encrypt message using AES
iv, encrypted_message = encrypt_aes(message, aes_key)

# Encrypt AES key using Bob's RSA public key
encrypted_aes_key = encrypt_rsa(aes_key, bob_public_key)

# Compute MAC for the encrypted message
mac_key = os.urandom(32)
mac = compute_mac(encrypted_message, mac_key)

# Encode bytes objects as base64 strings
iv_b64 = base64.b64encode(iv).decode()
encrypted_message_b64 = base64.b64encode(encrypted_message).decode()
encrypted_aes_key_b64 = base64.b64encode(encrypted_aes_key).decode()
mac_b64 = base64.b64encode(mac).decode()

# Create a dictionary to store the components
transmitted_data = {
    "iv": iv_b64,
    "encrypted_message": encrypted_message_b64,
    "encrypted_aes_key": encrypted_aes_key_b64,
    "mac": mac_b64
}

# Serialize the dictionary to JSON
transmitted_data_json = json.dumps(transmitted_data)

# Write the JSON data to the file
with open("Transmitted_Data.json", "w") as file:
    file.write(transmitted_data_json)
