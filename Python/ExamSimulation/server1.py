import socket
import sys

from myconfig import HOST, PORT
from mysecrets import lsb_d as d, lsb_n as n

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
print('Socket created')

try:
    s.bind((HOST, PORT))
except socket.error as msg:
    print('Bind failed. Error Code : ' + str(msg[0]) + ' Message ' + msg[1])
    sys.exit()
print('Socket bind complete')

s.listen(10)
print('Socket now listening')

#wait to accept a connection - blocking call
while 1:
    conn, addr = s.accept()
    print('A new RSA encrypted message received from ' + addr[0] + ':' + str(addr[1]))

    # receive the ciphertext
    ciphertext = conn.recv(4096)
    c = int.from_bytes(ciphertext,byteorder='big')
    # decrypt it
    lsb =  pow(c,d,n) % 2
    # leak the LSB
    print(lsb)
    if lsb == 0:
        to_send = b'even'
    if lsb == 1:
        to_send = b'odd'
    conn.send(to_send)

    conn.close()

s.close()
