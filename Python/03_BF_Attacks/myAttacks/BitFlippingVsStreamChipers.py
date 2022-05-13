import base64

from Crypto.Cipher import ChaCha20
from Crypto.Random import get_random_bytes

if __name__ == '__main__':
    #set up a stream cipher to break
    ###
    #This is Alice that wants to send money to Bob and she send to her bank the notification to pay Bob some money
    #to be secure (not so much) Alice and the bank use a streamcipher to encrypt the messages they exchange
    #they also share a key and a nonce
    ###
    key = get_random_bytes(ChaCha20.key_size)
    nonce = get_random_bytes(12)
    plaintext = b'Hello my Bank, I am Alice, from my bank account send to Bob 1000'
    print("Original Message")
    print(plaintext)
    cipher = ChaCha20.new(key=key, nonce=nonce)
    ciphertext = cipher.encrypt(plaintext)

    print("Ciphertext= " + base64.b64encode(ciphertext).decode())

    #I'm Bob and I want more money, I act like a man in the middle between Alice and her bank,
    #I intercept the ciphertext of the message that Alice send to the bank
    #and I modify how many money they have to send to me with a bit flipping attack against their stream cipher

    #since messages between bank and user follow a specific pattern Bob knows the position of the bit to flip to get more money
    index = plaintext.index(b'1')

    new_number_to_inject = b'9'
    unicode_int_to_inkect = ord(new_number_to_inject)

    #create the mask
    mask = ord(b'1') ^ unicode_int_to_inkect

    #let the ciphertext an editable item
    edt_ciphertext = bytearray(ciphertext)

    #performe the modification in the ciphertext
    edt_ciphertext[index] = edt_ciphertext[index] ^ mask

    #now that Bob has modified the ciphertext he can send the new one to cheat and gain more money

    ###
    #This is the bank perfoming decryptio
    ###

    cipher = ChaCha20.new(key=key, nonce=nonce)
    decrypted_msg = cipher.decrypt(edt_ciphertext)
    print("Message received from the Bank")
    print(decrypted_msg)