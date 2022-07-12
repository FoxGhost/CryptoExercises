from pwn import *
import string

from myconfig import HOST, PORT
from Crypto.Cipher import AES

SECRET_LEN = 16
secret=""

fix = " - and the key:"

for i in range(0,SECRET_LEN):
    pad = "A"*(AES.block_size-i)
    for letter in string.printable:

        server = remote(HOST, PORT)

        msg = fix+secret+letter+pad
        print("Sending: "+msg)
        server.send(msg)
        ciphertext = server.recv(1024).decode()

        server.close()

        if ciphertext[16:32] == ciphertext[48:64]:
            print("Found new character = "+letter)
            secret+=letter
            fix = fix[1:]
            break