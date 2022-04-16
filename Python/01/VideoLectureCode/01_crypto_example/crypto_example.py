from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES

if __name__ == '__main__':

    IV = get_random_bytes(AES.block_size)

    key = get_random_bytes(AES.key_size[2])

    plaintext = b'These are the data to encrypt !!'
    print(len(plaintext)) #multiple of 32

    cipher_enc = AES.new(key, AES.MODE_CBC, IV)
    ciphertext = cipher_enc.encrypt(plaintext)
    print(ciphertext)

    cipher_dec = AES.new(key, AES.MODE_CBC, IV)
    decrypted_data = cipher_dec.decrypt(ciphertext)
    print(decrypted_data)


