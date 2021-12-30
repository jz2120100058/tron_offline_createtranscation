from pprint import pprint
import hashlib

# !pip install requests
import requests

# !pip install base58
import base58

# !pip install ecdsa
import ecdsa

# !pip install pycryptodome
from Crypto.Hash import keccak

from tronpy.keys import PrivateKey
from tronpy.keys import PublicKey

API_BASE_URL = 'https://api.nileex.io'

MY_PRIV_KEY = 'ace2bf8f884680d036d8a855e338cc5af6a93473608b8d9a2b943019c2a3f42a'

TO_ADDR = "TVswGrmmPeaa9qxDq7FQWrhJ6A2bzxLvWp"

AMOUNT = 10000000


def keccak256(data):
    hasher = keccak.new(digest_bits=256)
    hasher.update(data)
    return hasher.digest()


def verifying_key_to_addr(key):
    pub_key = key.to_string()
    primitive_addr = b'\x41' + keccak256(pub_key)[-20:]
    addr = base58.b58encode_check(primitive_addr)
    return addr


print("=> my addr key")
raw_priv_key = bytes.fromhex(MY_PRIV_KEY)

priv_key = ecdsa.SigningKey.from_string(raw_priv_key, curve=ecdsa.SECP256k1)
pub_key = priv_key.get_verifying_key().to_string()
print('Pub Key:', pub_key.hex())

primitive_addr = b'\x41' + keccak256(pub_key)[-20:]
addr = base58.b58encode_check(primitive_addr)
print('My Addr:', addr)

print('=> createtransaction')
transaction = {
    "to_address": base58.b58decode_check(TO_ADDR).hex(),
    "owner_address": primitive_addr.hex(),
    "amount": AMOUNT,
}

resp = requests.post(API_BASE_URL + '/wallet/createtransaction', json=transaction)
payload = resp.json()

raw_data = bytes.fromhex(payload['raw_data_hex'])
signature = priv_key.sign_deterministic(raw_data, hashfunc=hashlib.sha256)

# recover address to get rec_id
pub_keys = ecdsa.VerifyingKey.from_public_key_recovery(
    signature[:64], raw_data, curve=ecdsa.SECP256k1, hashfunc=hashlib.sha256
)
for v, pk in enumerate(pub_keys):
    if verifying_key_to_addr(pk) == addr:
        break

signature += bytes([v])


# private_key_string = "ace2bf8f884680d036d8a855e338cc5af6a93473608b8d9a2b943019c2a3f42a"
# private_key_bytes = bytes.fromhex(private_key_string)    #十六进制字符串转换成十六进制字符数组
# pri_key = ecdsa.SigningKey.from_string(private_key_bytes, curve=ecdsa.SECP256k1)
# public_key_bytes = pri_key.get_verifying_key().to_string() #获取公钥并转换成字符串
#
# public_key = PublicKey(public_key_bytes)
# private_key = PrivateKey(private_key_bytes)
# txID_bytes = bytes.fromhex(payload["txID"])
# sig = private_key.sign_msg_hash(txID_bytes)
# signature_jz = sig.hex()

print('signature =', signature.hex())
payload['signature'] = [signature.hex()]

pprint(payload)

print('=> broadcasttransaction')
resp = requests.post(API_BASE_URL + '/wallet/broadcasttransaction', json=payload)

result = resp.json()

pprint(result)
if 'message' in result:
    print('Message:', bytes.fromhex(result['message']))