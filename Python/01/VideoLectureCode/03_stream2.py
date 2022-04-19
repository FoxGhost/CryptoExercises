import base64
import json

from Crypto.Cipher import Salsa20, AES
from Crypto.Random import get_random_bytes

import sys

from Crypto.Util.Padding import pad

if __name__ == '__main__':
    # key = get_random_bytes(Salsa20.key_size[1])
    # nonce = get_random_bytes(8)
    #
    # cipher = Salsa20.new(key=key, nonce=nonce)
    #
    # f_output = open(sys.argv[2], "wb")
    #
    # ciphertext = b''
    #
    # with open(sys.argv[1],"rb") as f_input:
    #     plaintext = f_input.read(1024)
    #     while plaintext:
    #         ciphertext += cipher.encrypt(plaintext)
    #         f_output.write(ciphertext)
    #         plaintext = f_input.read(1024)
    #
    # print("Nonce = " + base64.b16encode(cipher.nonce).decode())

    key = get_random_bytes(AES.key_size[0])
    iv = get_random_bytes(AES.block_size)

    f_input = open(__file__, "rb")

    cipher = AES.new(key, AES.MODE_CBC, iv)

    ciphertext = cipher.encrypt(pad(f_input.read(),AES.block_size))

    f_output = open("enc.enc", "wb")

    f_output.write(ciphertext)

    print(base64.b64encode(iv))

    result = json.dumps({'ciphertext': base64.b64encode(ciphertext).decode(), 'iv': base64.b64encode(iv).decode()})
    print(result)

    #the recipient has received result
    # ready to decrypt

    b64_out = json.loads(result)
    iv_rec = base64.b64decode(b64_out['iv'])
    ciphertext_rec = base64.b64decode(b64_out['ciphertext'])
    cipher_dec = AES.new(key, AES.MODE_CBC, iv_rec)
    plaintext_rec = cipher_dec.decrypt(ciphertext_rec)

    print(plaintext_rec)

