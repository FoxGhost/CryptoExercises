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
    7 block:  the secret is:* -> the block with the secret char
    8 block: ****************
    9 block: *********ppppppp

    1 block: Here is the mess
    2 block: age:AAAAAAAAAAAA -> 
    3 block: AAAAAAAAAA- and  -> there is no need to modify this pad
    4 block: the secret is:H1 -> the postfix reduce for the encreasing of the secret
    5 block: AAAAAAAAAAAAAAAA ->
    6 block: AAAAAAAAA - and  -> this pad is reducing for aligning the blocks to compare
    7 block: the secret is:** -> the block with the secret char
    8 block: ****************
    9 block: ********pppppppp

    1 block: Here is the mess
    2 block: age:AAAAAAAAAAAA  
    3 block: AAAAAAAAAA - and 
    4 block: Here's my very l 
    5 block: AAAAAAAAAA - an 
    6 block: d the secret is: 
    7 block: ****************
    8 block: *********ppppppp

    1 block: Here is the mess
    2 block: age:AAAAAAAAAAAA  
    3 block: AAAAAAAAAAHere's 
    4 block:  my very long se 
    5 block: AAAAA - and the  
    6 block: secret is:******
    7 block: ****************
    8 block: ****pppppppppppp
"""
if __name__ == '__main__':

    BLOCK_SIZE = AES.block_size
    BLOCK_SIZE_HEX = 2 * BLOCK_SIZE

    secret = ""

    prefix = "Here is the message:"
    postfix = " - and the secret is:"
    postfix_len = len(postfix)

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

                if i >= postfix_len:
                    postfix_pad = postfix_pad[1:]
                    padding = padding[1:]
                break

    print("The secret is: " + secret)