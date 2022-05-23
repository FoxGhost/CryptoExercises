from Crypto.Util.number import getPrime
from math import gcd

n_length = 1024

prime1 = getPrime(n_length)
prime2 = getPrime(n_length)

print("p1 = " + str(prime1))
print("p2 = " + str(prime2))

n = prime1 * prime2
print("n= " + str(n))

phi = (prime1 -1) * (prime2 - 1)

#define the public exponent
e = 65537

g = gcd(e, phi)
print(g)
if g != 1:
    raise ValueError

d = pow(e, -1, phi)
print("d = " + str(d))

public_rsa_key = (e, n)
private_rsa_key = (d, n)

#encryption
msg = b'this is the message to encrypt'
msg_int = int.from_bytes(msg, byteorder='big')
print("msg = " + str(msg_int))

if msg_int > n-1:
    raise ValueError

C = pow(msg_int, e, n)
print("ciphertext = " + str(C))

D = pow(C, d, n)
print("deciphered int = " + str(D))

msg_dec = D.to_bytes(n_length, byteorder='big')
print("msg = " + str(msg_dec))
print(msg.decode())


