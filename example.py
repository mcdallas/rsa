import rsa

private, public = rsa.generate_keypair(256)

message = b'deadbeef'

ciphertext = rsa.encrypt(message, public)

plaintext = rsa.decrypt(ciphertext, private)

assert plaintext == message
print('It works!')
