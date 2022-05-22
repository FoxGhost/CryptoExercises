import os
os.environ['PWNLIB_NOTERM'] = 'True'
os.environ['PWNLIB_SILENT'] = 'True'
from pwn import *

from myconfig import HOST, PORT
from mydata import cbc_oracle_iv as iv
from mydata import cbc_oracle_ciphertext as ciphertext

from Crypto.Cipher import AES
"""
if __name__ == '__main__':

    #first compute the number of blocks
    N = len(ciphertext)//AES.block_size
    print("Number of blocks: " + str(N))

    block_to_manipulate = bytearray(ciphertext[AES.block_size*(N-2):AES.block_size*(N-1)])
    last_block = ciphertext[AES.block_size*(N-1):]
    initial_part = ciphertext[:AES.block_size * (N - 2)]

    byte_index = AES.block_size - 1 #because index from 0-15

    #notation from slides c_15 last byte from the ciphertext
    c_15 = block_to_manipulate[byte_index]#original value

    #iterate to find c'15
    for c_prime_15 in range(0,256):
        #assign the value
        block_to_manipulate[byte_index] = c_prime_15
        #recompose ciphertext
        new_ciphertext = initial_part + block_to_manipulate + last_block

        #server connection
        server = remote(HOST,PORT)
        server.send(iv)
        server.send(new_ciphertext)
        response = server.recv(1024)
        server.close()

        #check
        if response == b'OK':
            #math part
            print("C'15: " + str(c_prime_15))
            p_prime_15 = c_prime_15 ^ 1
            p_15 = c_15 ^ p_prime_15
            print("P'15: " + str(p_prime_15))
            print("P15: " + str(p_15))
            break # to avoid the second result that it's a false positive
    #p_prime_15 = 81
    print("------------------")

    c_second_15 = 2 ^ p_prime_15
    block_to_manipulate[byte_index] = c_second_15
    byte_index -= 1

    c_14 = block_to_manipulate[byte_index]

    for c_prime_14 in range(256):

        block_to_manipulate[byte_index] = c_prime_14
        new_ciphertext = initial_part + block_to_manipulate + last_block

        # server connection
        server = remote(HOST, PORT)
        server.send(iv)
        server.send(new_ciphertext)
        response = server.recv(1024)
        server.close()

        if response == b'OK':
            #math part
            p_prime_14 = c_prime_14 ^ 2
            p14 = c_14 ^ p_prime_14

            print("C'14: " + str(c_prime_15))
            print("P'14: " + str(p_prime_15))
            print("P14: " + str(p_15))
    print("------------------")
"""


def block_numbers(ciphertext, block_size):
    return len(ciphertext)//block_size

def get_block_n(ciphertext, n, block_size):
    return ciphertext[(n) * block_size: (n+1) * block_size]


def guess_byte(p, c, ciphertext, block_size):
    c_prime = len(p) + 1
    n = block_numbers(ciphertext, block_size)
    current_byte_index = len(ciphertext)-1 -block_size - len(p)
    #ciphetext len -1 because of index starting from 0
    # - block size because I have to work on the previous block
    # - len(p) for been on the correct byte of the block

    plain = b'\x00'

    for i in range(0, 256):
        #build the new ciphertext modified in the index position
        new_ciphertext = bytearray()
        new_ciphertext += ciphertext[:current_byte_index]
        new_ciphertext += i.to_bytes(1, byteorder='big')

        for x in p:
            new_ciphertext += (x ^ c_prime).to_bytes(1, byteorder='big')

        new_ciphertext += get_block_n(ciphertext, n-1, block_size)

        # server connection
        server = remote(HOST, PORT)
        server.send(iv)
        server.send(new_ciphertext)
        response = server.recv(1024)
        server.close()

        # check
        if response == b'OK':
            # math part
            p_prime = c_prime ^ i
            plain = bytes([p_prime ^ ciphertext[current_byte_index]])
            if plain == b'\x01':
                continue
            c.insert(0, i)
            p.insert(0, p_prime)
    return plain



def guess_byte_first_block(p, c, ciphertext, block_size):
    pass


if __name__ == '__main__':

    n = block_numbers(ciphertext, AES.block_size)
    plaintext = bytearray()
    for i in range(1, n):    #for each block except for the first
        #the variables on which perform calculus
        c = [] 
        p = []
        
        #for each byte of the current block
        for j in range(0,AES.block_size):
            plaintext[0:0] = guess_byte(p, c, ciphertext, AES.block_size)
        ciphertext = ciphertext[:-AES.block_size]#???

    print("Ciphertext len: " + str(len(ciphertext)))
    #for the first block
    c = []
    p = []
    """
    for i in range(0, AES.block_size):
        plaintext[0:0] = guess_byte_first_block(p, c, ciphertext, AES.block_size)
    """
    print(plaintext)
