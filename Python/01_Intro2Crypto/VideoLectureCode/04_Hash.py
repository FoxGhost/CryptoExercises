import base64
import json

from Crypto.Hash import SHA256
from Crypto.Hash import SHA3_256
from Crypto.Random import get_random_bytes
from Crypto.Hash import HMAC

if __name__ == '__main__':
    hash_generator = SHA256.new()

    hash_generator.update(b'text to hash')
    hash_generator.update(b' even more text')

    print(hash_generator.hexdigest())
    print(hash_generator.digest())

    hash_generator = SHA256.new(data=b'initial bytes')
    hash_generator.update(b'text to hash')
    hash_generator.update(b' even more text')

    print(hash_generator.hexdigest())
    print(hash_generator.digest())


    #hash of a file
    hash_generator = SHA3_256.new()

    with open(__file__) as f_input:
        hash_generator.update(f_input.read().encode())

    print(hash_generator.hexdigest())

    #MAC
    msg = b'This is the message used in input'

    #secret = get_random_bytes(32)
    secret = b'deadbeefdeadbeefdeadbeefdeadbeef'

    hmac_generator = HMAC.new(secret, digestmod= SHA3_256)

    hmac_generator.update(msg)
    #hmac_generator.update(msg[:5])
    #hmac_generator.update(msg[5:])


    print(hmac_generator.hexdigest())

    obj = json.dumps({'message': msg.decode(), 'MAC': base64.b64encode(hmac_generator.digest()).decode()})
    print(obj)

    # ----
    b64_obj = json.loads(obj)
    hmac_verifier = HMAC.new(secret, digestmod=SHA3_256)

    hmac_verifier.update(b64_obj['message'].encode())

    mac = bytearray(base64.b64decode(b64_obj['MAC'].encode()))
    mac[0] = 0;

    try:
        #hmac_verifier.verify(base64.b64decode(b64_obj['MAC'].encode()))
        hmac_verifier.verify(mac)
        print("The message is authentic")
    except ValueError:
        print("Wrong message or secret")



















