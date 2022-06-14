import os
os.environ['PWNLIB_NOTERM'] = 'True'  # Configuration patch to allow pwntools to be run inside of an IDE
os.environ['PWNLIB_SILENT'] = 'True'
from pwnlib.tubes.remote import remote

from myconfig import HOST,PORT
from mysecrets import lsb_n as n, lsb_e as e
from mysecrets import lsb_ciphertext as ciphertext

def to_bytes(m,l=n.bit_length()):
    return int.to_bytes(m, l, byteorder='big')

def to_int(b):
    return int.from_bytes(b,byteorder='big')

def print_bounds(low, up):
    print("[" + str(low) + "," + str(up) + "]")

ciphertext=b's|xf5|×8d\xd0|x8d|xeb\x02&A\xa4\xff\xd2|xc3%ht|x95|xe1)|xb2|xcc/xfc|xee|x18\x12}x11)\xee\xec\xa6'

# init the bounds
upper_bound = n
lower_bound = 0
print_bounds(lower_bound,upper_bound)


m = int.from_bytes(ciphertext, byteorder='big')

for i in range(n.bit_length()):
    m = (pow(2, e, n) * m) % n

    # interact with the server
    server = remote(HOST, PORT)
    server.send(to_bytes(m))
    bit = server.recv(1024)
    server.close()
    print(bit)

    # update bounds based on the leaked LSB
    if  bit[0] == 'odd':
        lower_bound = (upper_bound + lower_bound) // 2
    else:
        upper_bound = (upper_bound + lower_bound) // 2
    print_bounds(lower_bound, upper_bound)


#print decoded message
print(to_bytes(lower_bound,n.bit_length()).decode())
