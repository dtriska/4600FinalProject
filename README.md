# 4600FinalProject

# Generate Alice's private key
openssl genpkey -algorithm RSA -out alice_private_key.pem

# Extract Alice's public key
openssl rsa -pubout -in alice_private_key.pem -out alice_public_key.pem

# Generate Bob's private key
openssl genpkey -algorithm RSA -out bob_private_key.pem

# Extract Bob's public key
openssl rsa -pubout -in bob_private_key.pem -out bob_public_key.pem






