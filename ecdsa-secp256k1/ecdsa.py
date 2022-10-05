from web3 import Web3
from eth_account.messages import encode_defunct

KEYSTORE_LOCATION = 'path/to/keystore'
KEYSTORE_FILE = 'keystore-file-name'
GETH_IPC = '/path/to/geth/ipc'

w3 = Web3(Web3.IPCProvider(GETH_IPC, timeout=60000))

# given a keystore file, use the key to sign a message that can be recovered in Solidity


def to_32byte_hex(val):
    return Web3.toHex(Web3.toBytes(val).rjust(32, b'\0'))


def load_privatekey_geth():
    with open(KEYSTORE_LOCATION + '/' + KEYSTORE_FILE) as keyfile:
        encrypted_key = keyfile.read()
        private_key = w3.eth.account.decrypt(encrypted_key, '')
        return private_key


def sign_message(privatekey, msg):
    # encode message in format that is backwards compatible with web3.eth.sign
    # https://eth-account.readthedocs.io/en/stable/eth_account.html#eth_account.messages.encode_defunct
    message = encode_defunct(text=msg)

    signed_message = w3.eth.account.sign_message(message, privatekey)
    return signed_message


def print_ec_recover_args(signed_message):
    ec_recover_args = (msghash, v, r, s) = (
        Web3.toHex(signed_message.messageHash),
        signed_message.v,
        to_32byte_hex(signed_message.r),
        to_32byte_hex(signed_message.s),
    )
    print(ec_recover_args)


privatekey = load_privatekey_geth()
msg = 'Hello World'
signed_message = sign_message(privatekey, msg)
print_ec_recover_args(signed_message)
