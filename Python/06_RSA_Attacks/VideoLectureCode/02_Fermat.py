from Crypto.Util.number import getPrime
from Crypto.Util.number import getRandomInteger

from gmpy2 import next_prime
from gmpy2 import isqrt

from timeit import default_timer as timer

if __name__ == '__main__':
    n = 400
    p1 = getPrime(n)
    delta = getRandomInteger(210)
    p2 = next_prime(p1 + delta)#the first half of the number is the same because delta is n/2

    print(p1)
    print(p2)

    n = p1 * p2
    # a^2 - b^2 = n = (a+b)(a-b)
    # a --> independent variable
    # b will be dependent on n, a
    # b^2 = a^2 - n

    start = timer()

    a = b = isqrt(n)
    b2 = pow(a,2) - n
    print("a = " + str(a))
    print("b = " + str(b))
    print("b2 = " + str(b2))
    print("delta--> " + str(pow(b,2)-b2 % n))

    i = 0

    while True:
        print("Iteration #" + str(i))
        if b2 == pow(b,2):
            print("Solution found")
            break
        else:
            a += 1
            b2 = pow(a, 2) - n
            b = isqrt(b2)
            #print("a = " + str(a))
            #print("b = " + str(b))
            #print("b2 = " + str(b2))
            #print("delta--> " + str(pow(b, 2) - b2 % n))

        i += 1

    p = a+b
    q = a-b
    end = timer()

    print(p)
    print(q)
    print("Time elapsed: ", (end-start)/60, "minutes")