# 4600FinalProject

# Generate a private key
openssl genpkey -algorithm RSA -out private_key.pem -pkeyopt rsa_keygen_bits:2048

# Extract the public key from the private key
openssl rsa -pubout -in private_key.pem -out public_key.pem

## Overview
This system facilitates secure communication between a sender and receiver using symmetric and asymmetric encryption, along with HMAC for message authentication. The sender encrypts a message using AES (Advanced Encryption Standard) with CBC (Cipher Block Chaining) mode, encrypts the AES key with RSA (Rivest-Shamir-Adleman), generates an HMAC (Hash-based Message Authentication Code) for integrity verification, and transmits the data securely. The receiver decrypts the AES key with RSA, verifies the HMAC, and decrypts the message using AES.

## System Design
The system consists of two main components:
1. Sender: Encrypts the message, encrypts the AES key, generates an HMAC, and transmits the data.
2. Receiver: Decrypts the AES key, verifies the HMAC, and decrypts the message.

### Algorithms Used
- **AES (Advanced Encryption Standard)**: Used for symmetric encryption of the message.
- **RSA (Rivest-Shamir-Adleman)**: Used for asymmetric encryption of the AES key.
- **HMAC (Hash-based Message Authentication Code)**: Used for message authentication.

### Key Lengths Used
- **AES Key**: 256 bits
- **RSA Key**: 2048 bits
- **HMAC Key**: 256 bits 

## How to Use
1. **Sender**
    - Place the plaintext message in a file named `message.txt`.
    - Ensure the receiver's RSA public key is available in a PEM format file named `public_key.pem`.
    - Run the sender code.
    - The encrypted message, IV, encrypted AES key, HMAC tag, and HMAC key will be saved in `Transmitted_Data.txt`.

2. **Receiver**
    - Ensure the sender has transmitted the data and provided the necessary files (`Transmitted_Data.txt`).
    - Ensure the receiver's RSA private key is available in a PEM format file named `private_key.pem`.
    - Run the receiver code.
    - The decrypted message will be printed if the HMAC verification succeeds.

Ensure the sender and receiver have the correct RSA key pairs and agree on the encryption and HMAC algorithms used.








