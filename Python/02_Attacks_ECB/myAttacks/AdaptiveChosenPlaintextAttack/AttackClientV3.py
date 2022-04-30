from Crypto.Cipher import AES

from myconfig import HOST, PORT

import os

os.environ['PWNLIB_NOTERM'] = 'True'  # Configuration patch to allow pwntools to be run inside of an IDE
os.environ['PWNLIB_SILENT'] = 'True'

from pwn import *

SECRET_LEN = 26

"""
    message = ""Here is the message:{0} - and the secret is:{1}"".format( input0, ecb_oracle_secret)
    I want to build an input so I can guess a char at the time of the secret

    Here is the message: -> 20 char -> AES.block_size = 16 so 

    1 block: Here is the mess
    2 block: age:AAAAAAAAAAAA -> in this case I need to pad the prefix
    3 block: AAAAAAAAAA - and -> also need to pad the postfix of my msg
    4 block:  the secret is:1 -> this is the block that I want to compare
    5 block: AAAAAAAAAAAAAAAA -> padding to align the blocks to compare
    6 block: AAAAAAAAAA - and -> ...
    7 block:  the secret is:* -> the block with the key char
    8 block: ***************p

    1 block: Here is the mess
    2 block: age:AAAAAAAAAAAA -> 
    3 block: AAAAAAAAAA- and  -> there is no need to modify this pad
    4 block: the secret is:H1 -> the postfix reduce for the encreasing of the secret
    5 block: AAAAAAAAAAAAAAAA ->
    6 block: AAAAAAAAA - and  -> this pad is reducing for aligning the blocks to compare
    7 block: the secret is:** -> the block with the key char
    8 block: **************pp

    do it until

    1 block: Here is the mess
    2 block: age:AAAAAAAAAAAA -> 
    3 block: AAAAAAAAAA - and -> there is no need to modify this pad
    4 block: Here's my secre1 -> the postfix reduce for the encreasing of the secret
    5 block: AAAAAAAAAAA - an ->
    6 block: d the secret is: -> this pad is reducing for aligning the blocks to compare
    7 block: **************** -> the block with the key char
"""
if __name__ == '__main__':

    BLOCK_SIZE = AES.block_size
    BLOCK_SIZE_HEX = 2 * BLOCK_SIZE

    secret = ""

    prefix = "Here is the message:"
    postfix = " - and the secret is:"

    prefix_pad_len = AES.block_size - (len(prefix) % AES.block_size)  # this is fix
    prefix_pad = "A" * prefix_pad_len

    postfix_pad_len = AES.block_size - ((len(postfix) + 1) % AES.block_size)  # this is fix
    postfix_pad = "A" * postfix_pad_len

    for i in range(0, SECRET_LEN):
        padding = "A" * (AES.block_size + postfix_pad_len - i)

        for char_to_guess in string.printable:
            msg = prefix_pad + postfix_pad + postfix + secret + char_to_guess + padding
            # print(msg)

            server = remote(HOST, PORT)
            server.send(msg)
            ciphertext = server.recv(10124)

            """
            for i in range(0, (len(ciphertext.hex()) // BLOCK_SIZE_HEX)):
                print(ciphertext.hex()[BLOCK_SIZE_HEX * i:BLOCK_SIZE_HEX * (i + 1)])
            """

            if ciphertext.hex()[BLOCK_SIZE_HEX * 3: BLOCK_SIZE_HEX * 4] == ciphertext.hex()[
                                                                           BLOCK_SIZE_HEX * 6: BLOCK_SIZE_HEX * 7]:
                print("Found: " + char_to_guess)
                secret += char_to_guess
                postfix = postfix[1:]
                break

    print("The secret is: " + secret)