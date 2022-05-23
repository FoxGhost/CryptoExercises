from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

#alice or bob
parameters = dh.generate_parameters(generator=2, key_size=1024, backend=default_backend())#fixed and long term
#alice
alice_private_key = parameters.generate_private_key()
#bob
bob_public_key = parameters.generate_private_key().public_key()#is the public key for communicating with alice
#alice
shared_secret = alice_private_key.exchange(bob_public_key)

derived_key = HKDF(
    algorithm=hashes.SHA256(),
    length=32,
    salt=None,
    info=b'just agreed data',
    backend= default_backend()
).derive(shared_secret)

#ephemeral
alice_private_key2 = parameters.generate_private_key()
bob_public_key2 = parameters.generate_private_key().public_key()
shared_secret2 = alice_private_key2.exchange(bob_public_key2)
derived_key2 = HKDF(
    algorithm=hashes.SHA256(),
    length=32,
    salt=None,
    info=b'just agreed data',
    backend= default_backend()
).derive(shared_secret2)