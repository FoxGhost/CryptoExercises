from myconfig import HOST, PORT
import os
os.environ['PWNLIB_NOTERM'] = 'True'
os.environ['PWNLIB_SILENT'] = 'True'

from pwn import *
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

if __name__ == '__main__':
    server = remote(HOST, PORT)

    username = b'foxghost'#pay attention to the length of the name, the string admin=0 must be all in the same block

    server.send(username)

    ###
    #the server has this line to generate the cookie
    #cookie = b'username='+username+b',admin=0'
    #I receive that cookie encrypted
    #since I know the cookie I want to perform a change to become admin
    #firsty forge the cookie to find in which position is the bit to flip
    #then understand in which block it is to perform the modification in the previuos one
    ###
    cookie = pad(b'username=' + username + b',admin=0', AES.block_size)

    for i in range(0, len(cookie)//AES.block_size):
        print(cookie[i*AES.block_size: (i+1)*AES.block_size])

    index = cookie.index(b'0')
    print("Index: " + str(index))
    index_in_the_block = index % AES.block_size
    print("Index in the block: " + str(index_in_the_block))
    block_to_bf = index // AES.block_size
    if block_to_bf >= 1:
        block_to_bf = block_to_bf - 1
    print('Block to modify: ' + str(block_to_bf))

    received_cookie = server.recv(1024)

    desired_value = ord(b'1')
    mask = ord(b'0') ^ desired_value

    edt_cookie = bytearray(received_cookie)

    edt_cookie[block_to_bf * AES.block_size + index_in_the_block] = edt_cookie[block_to_bf * AES.block_size + index_in_the_block] ^ mask

    server.send(edt_cookie)

    ans = server.recv(1024)
    print(ans)

    server.close()
