from Crypto.Random import get_random_bytes
from Crypto.Cipher import ChaCha20
import base64

if __name__ == '__main__':

    plaintext = b'this is the secret message...'
    plaintext_2 = b'This is additional text to encrypt'

    key = get_random_bytes(ChaCha20.key_size)
    nonce = get_random_bytes(12)
    print("Nonce = " + base64.b64encode(nonce).decode())


    #cipher = ChaCha20.new(key = key)#nonce is not specified, it could be leave empty but then you must save it
    cipher = ChaCha20.new(key=key, nonce=nonce)

    ciphertext = cipher.encrypt(plaintext)
    ciphertext += cipher.encrypt(plaintext_2)

    print("Ciphertext= " + base64.b64encode(ciphertext).decode())
    print("Nonce = " + base64.b64encode(cipher.nonce).decode())#same of before if not declared it's auto generated

