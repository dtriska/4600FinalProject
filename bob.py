import json
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import hmac
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
from cryptography.exceptions import InvalidSignature

def decrypt_rsa(ciphertext, private_key):
    plaintext = private_key.decrypt(
        ciphertext,
        asym_padding.OAEP(
            mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return plaintext

def decrypt_aes(ciphertext, key, iv):
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded_data = decryptor.update(ciphertext) + decryptor.finalize()

    unpadder = padding.PKCS7(128).unpadder()
    data = unpadder.update(padded_data) + unpadder.finalize()

    return data

def verify_mac(message, key, mac):
    h = hmac.HMAC(key, hashes.SHA256(), backend=default_backend())
    h.update(message)
    try:
        h.verify(mac)
        return True
    except InvalidSignature:
        return False

# Load Bob's RSA private key
with open("bob_private_key.pem", "rb") as key_file:
    bob_private_key = serialization.load_pem_private_key(
        key_file.read(),
        password=None,
        backend=default_backend()
    )

# Load Alice's RSA public key
with open("alice_public_key.pem", "rb") as key_file:
    alice_public_key = serialization.load_pem_public_key(
        key_file.read(),
        backend=default_backend()
    )

# Read transmitted data from JSON file
with open("Transmitted_Data.json", "r") as file:
    transmitted_data_json = file.read()

# Parse JSON to get individual components
transmitted_data = json.loads(transmitted_data_json)
iv = transmitted_data["iv"]
encrypted_message = transmitted_data["encrypted_message"]
encrypted_aes_key = transmitted_data["encrypted_aes_key"]
mac = transmitted_data["mac"]

# Decrypt AES key using Bob's RSA private key
aes_key = decrypt_rsa(encrypted_aes_key, bob_private_key)

# Decrypt message using AES key
message = decrypt_aes(encrypted_message, aes_key, iv)

# Verify MAC to authenticate the message
if verify_mac(message, aes_key, mac):
    print("Message authenticated and decrypted successfully:")
    print(message.decode())
else:
    print("MAC verification failed. Message may have been tampered with.")
