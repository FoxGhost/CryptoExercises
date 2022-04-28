from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

from myconfig import HOST, PORT

import os
os.environ['PWNLIB_NOTERM'] = 'True'  # Configuration patch to allow pwntools to be run inside of an IDE
os.environ['PWNLIB_SILENT'] = 'True'

from pwn import *

from ECB_CopyPaste_server_genCookie_service import profile_for,encode_profile

if __name__ == '__main__':
    from Crypto.Cipher import AES
    from Crypto.Util.Padding import pad

    from myconfig import HOST, PORT

    import os

    os.environ['PWNLIB_NOTERM'] = 'True'  # Configuration patch to allow pwntools to be run inside of an IDE
    os.environ['PWNLIB_SILENT'] = 'True'

    from pwn import *

    from ECB_CopyPaste_server_genCookie_service import profile_for, encode_profile

    """
    build a cookie to obtain admin rule like this
    email=anything@aaa.com&UID=XX&role=admin

    the server construct the cookie like this:
    - it takes the email 
    - then user id, it has two chars (number)
    - it knows the role
    then creates the string:

    "email="+email+"&UID"+id+"&role="+role

    I want that the first two block exactly like this:
    email=aaaaaa@b.it&UID=XX&role=

    then I start anther connection
    """
    mail_prefix = "email="
    mail = "a@b.it"
    postfix = "&UID=XX&role="

    msg = mail_prefix + mail + postfix

    if len(msg) == AES.block_size * 2:
        print("len ok")
    else:
        if len(msg) > AES.block_size * 2:
            n = len(msg) - AES.block_size * 2
            exit("reduce the message of ", n, "bytes")
        elif len(msg) < AES.block_size * 2:
            n = AES.block_size * 2 - len(msg)
            print("increased the mail of ", n, "bytes")
            mail = 'a'*n + mail

    server = remote(HOST, PORT)

    server.send(mail)
    enc1 = server.recv(1024)
    server.close()

    """
    Now I have the first 2 blocks encrypted: 
    email=aaaaaaaa@b.it&UID=XX&role=

    I have to encrypt a last block to have the word admin encrypted, 
    the block should look like this:
    the first must end exactly for let start the word admin in the second block
    email=aaaaaaaaa|admin........ 
    
    DON'T forget the paddin of admin
    """

    msg = b'aaaaaaaaaa'

    if len(msg.decode() + mail_prefix) == AES.block_size:
        print("len ok")
    else:
        if len(msg) > AES.block_size:
            n = len(msg) - AES.block_size
            exit("reduce the second message of ", n, "bytes")
        elif len(msg) < AES.block_size:
            n = AES.block_size - len(msg)
            print("increased the second message of ", n, "bytes")
            #msg = 'a' * n + msg

    msg = msg + pad(b'admin', AES.block_size)

    server = remote(HOST, PORT)
    server.send(msg)
    enc2 = server.recv(1024)
    server.close()

    """
    now take the needed pieces from the two encrypted cookies to have the desired one
    from the first cookie take the first and second block
    from the second cookie take the second block
    """

    new_cookie = enc1[0:AES.block_size * 2] + enc2[AES.block_size:AES.block_size * 2]

    adminTestServer = remote(HOST, PORT + 100)
    adminTestServer.send(new_cookie)
    aswer = adminTestServer.recv(1024)

    print(aswer.decode())
