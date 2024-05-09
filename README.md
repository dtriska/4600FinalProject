# 4600FinalProject

Alice Key Gen
openssl genpkey -algorithm RSA -out alice_private.pem -aes256
openssl rsa -pubout -in alice_private.pem -out alice_public.pem

Bob Key Gen
openssl genpkey -algorithm RSA -out bob_private.pem -aes256
openssl rsa -pubout -in bob_private.pem -out bob_public.pem

Encrypt AES
openssl rand -base64 32 > aes_key.txt

Encrypt Alices Message
openssl enc -aes-256-cbc -in alice_message.txt -out alice_encrypted.txt -pass file:aes_key.txt

Encrypt Bobs Message
openssl enc -aes-256-cbc -in bob_message.txt -out bob_encrypted.txt -pass file:aes_key.txt

