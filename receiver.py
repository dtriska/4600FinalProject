from cryptography.hazmat.primitives import padding, hashes
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hmac
from cryptography.hazmat.primitives.asymmetric import padding as asymmetric_padding

# Decrypts a message using AES decryption algorithm with a given AES key and IV
def decrypt_message_with_aes(encrypted_message, iv, aes_key):
    backend = default_backend()
    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=backend)
    decryptor = cipher.decryptor()
    decrypted_message = decryptor.update(encrypted_message) + decryptor.finalize()
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    unpadded_message = unpadder.update(decrypted_message) + unpadder.finalize()
    return unpadded_message

# Decrypts an AES key using RSA decryption algorithm with a given RSA private key
def decrypt_aes_key_with_rsa(encrypted_aes_key, rsa_private_key):
    decrypted_aes_key = rsa_private_key.decrypt(
        encrypted_aes_key,
        asymmetric_padding.OAEP(
            mgf=asymmetric_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return decrypted_aes_key

# Verifies the integrity and authenticity of data using HMAC
def verify_hmac(key, data, hmac_tag):
    h = hmac.HMAC(key, hashes.SHA256(), backend=default_backend())
    h.update(data)
    try:
        h.verify(hmac_tag)
        print("Verified Signature")
        return True
    except hmac.InvalidSignature:
        print("Invalid Signature")
        return False

with open("private_key.pem", "rb") as private_key_file:
    private_key = serialization.load_pem_private_key(
        private_key_file.read(),
        password=None,
        backend=default_backend()
    )

# Load transmitted data from the single file
with open("Transmitted_Data.txt", "rb") as file:
    transmitted_data = file.read()

# Extract data from the transmitted data
iv_size = 16
aes_key_size = 256
hmac_key_size = 32

iv = transmitted_data[:iv_size]
encrypted_aes_key = transmitted_data[iv_size: iv_size + aes_key_size]
encrypted_message = transmitted_data[iv_size + aes_key_size: -hmac_key_size * 2]
hmac_tag = transmitted_data[-hmac_key_size * 2: -hmac_key_size]
hmac_key = transmitted_data[-hmac_key_size:]

# Decrypt AES key with RSA
aes_key = decrypt_aes_key_with_rsa(encrypted_aes_key, private_key)

# Verify HMAC
if verify_hmac(hmac_key, encrypted_message + iv + encrypted_aes_key, hmac_tag):
    # Decrypt message with AES
    decrypted_message = decrypt_message_with_aes(encrypted_message, iv, aes_key)
    print("Decrypted Message:", decrypted_message.decode())
else:
    print("HMAC verification failed. Data may have been tampered with.")

