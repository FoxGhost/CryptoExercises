import os
os.environ['PWNLIB_NOTERM'] = 'True'  # Configuration patch to allow pwntools to be run inside of an IDE
os.environ['PWNLIB_SILENT'] = 'True'
from pwnlib.tubes.remote import remote

import decimal

from myconfig import HOST,PORT
from mysecrets import lsb_n as n, lsb_e as e
from mysecrets import lsb_ciphertext as ciphertext

def print_bounds(low, up):
    print("[" + str(low) + "," + str(up) + "]")

if __name__ == '__main__':
    #server = remote(HOST, PORT)
    #server.send(ciphertext.to_bytes(n.bit_length(), byteorder='big'))#assume to have previoulsy sniffed the ciphertext it was encoded as int
    #bit = server.recv(1024)
    #print(bit.hex())
    #server.close()

    decimal.getcontext().prec = n.bit_length()# to be sure to have the correct precision
    #upper_bound = n
    upper_bound = decimal.Decimal(n)
    #lower_bound = 0
    lower_bound = decimal.Decimal(0)
    print_bounds(lower_bound, upper_bound)

    m = ciphertext#assume to have previoulsy sniffed the ciphertext it was encoded as int
    for i in range(n.bit_length()):
        m = (pow(2,e,n) * m) % n

        server = remote(HOST, PORT)
        server.send(m.to_bytes(n.bit_length(), byteorder='big'))
        bit = server.recv(1024)
        print(bit.hex())
        server.close()

        if bit[0] == 1:
            lower_bound = (lower_bound + upper_bound) / 2#// 2
        else:
            upper_bound = (lower_bound + upper_bound) / 2#// 2

        print_bounds(lower_bound, upper_bound)
    print(int(upper_bound).to_bytes(n.bit_length(), byteorder='big').decode())
    #without a proper library the last char will be wrong since python has a problem with the representation of such big numbers

