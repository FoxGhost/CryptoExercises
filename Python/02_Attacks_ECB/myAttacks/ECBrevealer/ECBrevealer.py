import os
os.environ['PWNLIB_NOTERM'] = 'True'  # Configuration patch to allow pwntools to be run inside of an IDE
os.environ['PWNLIB_SILENT'] = 'True'

from pwn import *
from Crypto.Cipher import AES

from myconfig import HOST,PORT

BLOCK_SIZE = AES.block_size
BLOCK_SIZE_HEX = 2*BLOCK_SIZE

"""
server = remote(HOST, PORT)#connecting to the server

test_msg = 'A' * 16

print("Sending: " + test_msg)

server.send(test_msg)

recieved = server.recv(1024)
print("Received: " + recieved.hex())

server.close()
"""
"""
after this attempt I look into the server side terminal and I discorver this print:
This is what I received: AAAAAAAAAAAAAAAA -- END OF MESSAGE

the server add at the beginning: This is what I received: <- note the space after :
the server add at the ending: note that space-> -- END OF MESSAGE

So my message will be long len(This is what I received: ) + len(test_msg) + len( -- END OF MESSAGE)

I also know the server is using AES with CBC or EBC mode 

so the message must be padded for the length of the AES.block_size

len(This is what I received: ) = 25 - (AES.block_size = 16) = 9 the second block will start with 9 char of the intro
I have to complete the second bloc with 16-9=7 char so the pad will be:

pad_len =  len(This is what I received: ) % AES.block_size I'm interested in the remaining bytes

msg = 'A' * pad_len + 'A' * 2*AES.block_size

In this way I created 3 blocks all with the same char inside I can the postfix lex 

"""
prefix = "This is what I received: "
pad_len =  len(prefix) % AES.block_size #I'm interested in the remaining bytes
msg = 'A' * pad_len + 'A' * (2*AES.block_size)

server = remote(HOST, PORT)

#print("Sending: " + msg)
server.send(msg)

rec = server.recv(1024)
server.close()

rec_hex = rec.hex()
#print("Received: " + rec_hex)

for i in range(0, len(rec_hex)//BLOCK_SIZE_HEX):
    print(rec_hex[i*BLOCK_SIZE_HEX: (i+1)*BLOCK_SIZE_HEX])

print("Selected Mode is: ")
if rec_hex[2*BLOCK_SIZE_HEX: 3*BLOCK_SIZE_HEX] == rec_hex[3*BLOCK_SIZE_HEX: 4*BLOCK_SIZE_HEX]:
    print("ECB")
else:
    print("CBC")

"""
What if I don't know about the prefix len and the postfix len, but I know they are present?
I should create a message long enough to find it in the cipher text if it is encrypted in ECB mode
This is a more generic case
"""
msg = 'A' * AES.block_size * 3

server = remote(HOST, PORT)
server.send(msg)
rec = server.recv(1024)
server.close()

rec_hex = rec.hex()

print("Selected Mode is: ")
cbc = True

for i in range(0, len(rec_hex)//BLOCK_SIZE_HEX):
    print(rec_hex[i*BLOCK_SIZE_HEX: (i+1)*BLOCK_SIZE_HEX])

for i in range(0, len(rec_hex) // BLOCK_SIZE_HEX):
    if rec_hex[i*BLOCK_SIZE_HEX: (i+1)*BLOCK_SIZE_HEX] == rec_hex[(i+1)*BLOCK_SIZE_HEX: (i+2)*BLOCK_SIZE_HEX]:
        print("ECB")
        cbc = False
        break

if cbc:
    print("CBC")

