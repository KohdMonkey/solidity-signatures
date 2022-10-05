from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from pyrfc3339 import generate
from web3 import Web3
import sys

# KEYSIZEBITS = 1024
# KEYSIZEBITS = 2048
KEYSIZEBITS = 3072

# KEYSIZEBYTES = 128 # 1024 bits
# KEYSIZEBYTES = 256 # 2048 bits
KEYSIZEBYTES = 384  # 3072 bits


# source: https://gist.github.com/ostinelli/aeebf4643b7a531c248a353cee8b9461
def save_file(filename, content):
    # save file helper
    f = open(filename, "wb")
    f.write(content)
    f.close()


def generate_keys(keysizebits):
    # generate private key & write to disk  
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=keysizebits,
        backend=default_backend()
    )
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    save_file("private.pem", pem)

    # generate public key  
    public_key = private_key.public_key()
    pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    save_file("public.pem", pem)


def load_privatekey():
    with open("private.pem", "rb") as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=None,
        )
        return private_key
    return None


def load_publickey():
    with open("public.pem", "rb") as key_file:
        publickey = serialization.load_pem_public_key(
            key_file.read()
        )
        return publickey


def sign_message(private_key: rsa.RSAPrivateKey, message: bytes):
    signature = private_key.sign(
        message,
        padding.PKCS1v15(),
        hashes.SHA256()
    )
    return signature


def sign_with_output(keysize):
    keysizebytes = (int)(keysize / 8)
    publickey = load_publickey()

    pubNum = publickey.public_numbers()
    exponent = pubNum.e
    modulus = pubNum.n
    print('exponent:', Web3.toHex((exponent).to_bytes(keysizebytes, byteorder='big')))
    print('modulus:', Web3.toHex((modulus).to_bytes(keysizebytes, byteorder='big')))
    print()

    message = b'hello world'
    print('message:', Web3.toHex(message))
    print()

    privatekey = load_privatekey()
    signature = sign_message(privatekey, message)
    print('signature: ', Web3.toHex(signature))


if len(sys.argv) != 3:
    print('usage: ', sys.argv[0], ' [generate|sign] keysizeinbits(1024, 2048, 3072)')
    sys.exit(1)

# try parsing the keysize
try:
    keysize = int(sys.argv[2])
except:
    print('invalid number: ', sys.argv[2])
    sys.exit(1)

if sys.argv[1] == 'generate':
    generate_keys(keysize)
elif sys.argv[1] == 'sign':
    sign_with_output(keysize)
else:
    print(sys.argv[1], ' is not a valid function')