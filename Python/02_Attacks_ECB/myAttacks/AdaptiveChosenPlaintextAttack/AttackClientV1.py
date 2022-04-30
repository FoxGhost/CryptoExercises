from Crypto.Cipher import AES

from myconfig import HOST, PORT

import os

os.environ['PWNLIB_NOTERM'] = 'True'  # Configuration patch to allow pwntools to be run inside of an IDE
os.environ['PWNLIB_SILENT'] = 'True'

from pwn import *

SECRET_LEN = 16

"""
    message = ""Here is the msg:{0} - and the sec:{1}"".format( input0, ecb_oracle_secret)
    I want to build an input so I can guess a char at the time of the secret

    1 block: Here is the msg:
    2 block:  - and the sec:1
    3 block: AAAAAAAAAAAAAAAA
    4 block:  - and the sec:*
    5 block: ***************p
    
    1 block: Here is the msg:
    2 block: - and the sec:H1 -> after finding a char reduce this len of 1
    3 block: AAAAAAAAAAAAAAA  -> to have still the same block to check reduce also this of 1
    4 block: - and the sec:**
    5 block: ***************p
    
    do it until
    
    1 block: Here is the msg:
    2 block: Here's my secre1 -> last char to find 
    3 block: A - and the sec: -> pad = 1
    4 block: **************** -> the entire secret to confront
"""
if __name__ == '__main__':

    secret = ""

    prefix  = "Here is the msg:"
    postfix = " - and the sec:"


    for i in range(0, SECRET_LEN):
        padding = "A"*(AES.block_size-i)

        for char_to_guess in string.printable:
            msg = postfix+secret+char_to_guess+padding

            server = remote(HOST, PORT)
            server.send(msg)
            ciphertext = server.recv(10124)

            if ciphertext[AES.block_size:AES.block_size*2] == ciphertext[AES.block_size*3:AES.block_size*4]:
                print("Found: "+ char_to_guess)
                secret += char_to_guess
                postfix = postfix[1:]
                break

    print("The secret is: " + secret)