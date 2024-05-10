from cryptography.hazmat.primitives import padding, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hmac
from cryptography.hazmat.primitives.asymmetric import padding as asymmetric_padding
import os

def encrypt_message_with_aes(message, aes_key):
    iv = os.urandom(16)  # Initialization Vector
    backend = default_backend()
    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=backend)
    encryptor = cipher.encryptor()
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_message = padder.update(message) + padder.finalize()
    encrypted_message = encryptor.update(padded_message) + encryptor.finalize()
    return encrypted_message, iv

def encrypt_aes_key_with_rsa(aes_key, rsa_public_key):
    encrypted_aes_key = rsa_public_key.encrypt(
        aes_key,
        asymmetric_padding.OAEP(
            mgf=asymmetric_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return encrypted_aes_key

def generate_hmac(key, data):
    h = hmac.HMAC(key, hashes.SHA256(), backend=default_backend())
    h.update(data)
    return h.finalize()

# Load plaintext message
with open("message.txt", "rb") as file:
    plaintext = file.read()

# Generate AES key
aes_key = os.urandom(32)  # 256-bit AES key

# Encrypt message with AES
encrypted_message, iv = encrypt_message_with_aes(plaintext, aes_key)

# Load receiver's RSA public key
with open("public_key.pem", "rb") as key_file:
    public_key = serialization.load_pem_public_key(
        key_file.read(),
        backend=default_backend()
    )

# Encrypt AES key with RSA
encrypted_aes_key = encrypt_aes_key_with_rsa(aes_key, public_key)

# Generate HMAC key
hmac_key = os.urandom(32)  # Generate a random 32-byte HMAC key

# Calculate HMAC
h = hmac.HMAC(hmac_key, hashes.SHA256(), backend=default_backend())
h.update(encrypted_message + iv + encrypted_aes_key)
hmac_tag = h.finalize()

print("iv: ", iv)
print("Encrypted AES Key: ", encrypted_aes_key)
print("HMAC_Tag: ", hmac_tag)
print("Encrypted Message: ", encrypted_message)

# Write transmitted data to separate files
with open("Transmitted_IV.txt", "wb") as file:
    file.write(iv)

with open("Transmitted_Encrypted_AES_Key.txt", "wb") as file:
    file.write(encrypted_aes_key)

with open("Transmitted_Encrypted_Message.txt", "wb") as file:
    file.write(encrypted_message)

with open("Transmitted_HMAC_Tag.txt", "wb") as file:
    file.write(hmac_tag)

with open("Transmitted_HMAC_Key.txt", "wb") as file:
    file.write(hmac_key)  # Write the HMAC key to the file




