import hashlib
import hmac
from Crypto.Random import get_random_bytes

if __name__ == '__main__':

    dig_generator = hashlib.sha256()
    dig_generator.update(b'First chunk of data')
    dig_generator.update(b'Second chunk of data')

    print(dig_generator.hexdigest())

    secret = get_random_bytes(32)

    mac_generator = hmac.new(secret, b'message to hash', hashlib.sha256)

    hmac_sender = mac_generator.hexdigest()

    #--------------------------
    #verifier

    mac_gen_rec = hmac.new(secret, b'message to hash', hashlib.sha256)
    hmac_ver = mac_gen_rec.hexdigest()

    if hmac.compare_digest(hmac_sender, hmac_ver):
        print("HMAC are ok")
    else:
        print("HMAC are different")

