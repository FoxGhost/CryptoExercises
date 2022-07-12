import socket
import sys
from Crypto.Cipher import AES
#from Crypto.Util.Padding import pad

from mysecrets import ecb_oracle_key,ecb_oracle_secret
from myconfig import HOST, PORT


def pad ( message ) :
    if len(message) % 16 != 0:
        message = message + '0' * (16 - len(message)%16)
    return message


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
    print('A new encryption requested by ' + addr[0] + ':' + str(addr[1]))

    input0 = conn.recv(1024).decode()

    # ecb_oracle_secret is 16 bytes long, all printable strings
    message = """Here is the msg:{0} - and the key:{1}""".format( input0, ecb_oracle_secret)
    message = pad(message)
    cipher = AES.new( ecb_oracle_key.decode('hex'), AES.MODE_ECB )
    ciphertext = (cipher.encrypt(message).encode('hex')).encode('hex')

    conn.send(ciphertext)

    conn.close()

s.close()