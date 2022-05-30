from ExtendedEuclideanAlgoForGCD import egcd
from Crypto.PublicKey import RSA

def iroot (k, n):
    u ,s = n, n+1

    while u < s:
        s = u
        t = (k-1) * s + n // pow(s, k-1)
        u = t // k
    return s

if __name__ == '__main__':

    n_lenght = 1024
    e = 3

    rsa1 = RSA.generate(n_lenght, e=e)
    rsa2 = RSA.generate(n_lenght, e=e)
    rsa3 = RSA.generate(n_lenght, e=e)

    n1 = rsa1.n
    n2 = rsa2.n
    n3 = rsa3.n

    print(n1)
    print(n2)
    print(n3)

    print(rsa1.e)

    m = b'This is the message to decrypt'
    m_int = int.from_bytes(m, byteorder='big')

    c1 = pow(m_int, e, n1)
    c2 = pow(m_int, e, n2)
    c3 = pow(m_int, e, n3)

    #N = n1 * n2 * n3
    # c modulo N
    # c1, c2, c3, n1, n2, n3 known
    # m_int

    g, u1, v1 = egcd(n2 * n3, n1) #N / n1
    g, u2, v2 = egcd(n1 * n3, n2)  # N / n2
    g, u3, v3 = egcd(n1 * n2, n3)  # N / n2

    c = c1 * u1 * n2*n3 + c2 * u2 * n1*n3 + c3 * u3 * n1*n2

    dec_int = iroot(e, c)
    print(dec_int.to_bytes(dec_int.bit_length()//8 +1, byteorder='big').decode())