
import ecdsa
import time
import hashlib
import base58
from enum import Enum
from pprint import pprint
from tronpy import keys
from tronpy.keys import PrivateKey
from tronpy.keys import PublicKey
from tronpy.providers import HTTPProvider
from Crypto.Hash import keccak

class ContractType(Enum) :
      AccountCreateContract = 0;
      TransferContract = 1;
      TransferAssetContract = 2;
      VoteAssetContract = 3;
      VoteWitnessContract = 4;
      WitnessCreateContract = 5;
      AssetIssueContract = 6;
      WitnessUpdateContract = 8;
      ParticipateAssetIssueContract = 9;
      AccountUpdateContract = 10;
      FreezeBalanceContract = 11;
      UnfreezeBalanceContract = 12;
      WithdrawBalanceContract = 13;
      UnfreezeAssetContract = 14;
      UpdateAssetContract = 15;
      ProposalCreateContract = 16;
      ProposalApproveContract = 17;
      ProposalDeleteContract = 18;
      SetAccountIdContract = 19;
      CustomContract = 20;
      CreateSmartContract = 30;
      TriggerSmartContract = 31;
      GetContract = 32;
      UpdateSettingContract = 33;
      ExchangeCreateContract = 41;
      ExchangeInjectContract = 42;
      ExchangeWithdrawContract = 43;
      ExchangeTransactionContract = 44;
      UpdateEnergyLimitContract = 45;
      AccountPermissionUpdateContract = 46;
      ClearABIContract = 48;
      UpdateBrokerageContract = 49;
      ShieldedTransferContract = 51;
      MarketSellAssetContract = 52;
      MarketCancelOrderContract = 53;


owner_address = "TE7vGbxLHPGzW9LXdtLCXaRNv3a49PcDYv"
to_address = "TVswGrmmPeaa9qxDq7FQWrhJ6A2bzxLvWp"
amount = 10000000

#1.通过私钥获取公钥
private_key_string = "ace2bf8f884680d036d8a855e338cc5af6a93473608b8d9a2b943019c2a3f42a"
private_key_bytes = bytes.fromhex(private_key_string)    #十六进制字符串转换成十六进制字符数组
pri_key = ecdsa.SigningKey.from_string(private_key_bytes, curve=ecdsa.SECP256k1)
public_key_bytes = pri_key.get_verifying_key().to_string() #获取公钥并转换成字符串

public_key = PublicKey(public_key_bytes)
private_key = PrivateKey(private_key_bytes)

#2.构建交易
owner_address_hex = keys.to_hex_address(owner_address)
to_address_hex = keys.to_hex_address(to_address)
type = "TransferContract"
type_url = "type.googleapis.com/protocol." + type
type_url_byte = b"type.googleapis.com/protocol." + b"TransferContract"
type_url_hex = []
for i in range(len(type_url_byte)):
    type_url_hex.append((type_url_byte[i]))


#3.获取最新快块hash以及最新块bytes
fee_limit = 10000000
timeout = 10.0
network = "https://api.nileex.io"
provider = HTTPProvider(network, timeout)
info = provider.make_request("wallet/getnodeinfo")
ref_block_id = info["solidityBlock"].split(",ID:")[-1]
ref_block_bytes = ref_block_id[12:16]
ref_block_hash = ref_block_id[16:32]
txID = ""
timestamp = int(time.time() * 1000)
expiration = timestamp + 60000
signature = []
token_id = 1000496
asset_name = str(token_id).encode().hex()

constact = [
    {
        "parameter":{
            "value":{
                "owner_address" : owner_address_hex,
                "to_address" :to_address_hex,
                "amount": amount,
                # "asset_name": asset_name,

            },
            "type_url":type_url
        },
        "type": type
    }
]

raw_data = {
    "contract": constact,
    "ref_block_bytes": ref_block_bytes,
    "ref_block_hash": ref_block_hash,
    "expiration": expiration,
    "timestamp": timestamp,
    }

transcation = {
    "txID" : txID,
    "raw_data" : raw_data,
    "signature": signature
}

# #4.方法一，不需要自己组装raw_data_protobuf
# signweight = provider.make_request("wallet/getsignweight", transcation)
# transcation["txID"] = signweight["transaction"]["txid"]
# txID_bytes = bytes.fromhex(transcation["txID"])
# sig = private_key.sign_msg_hash(txID_bytes)
# signature.append(sig.hex())
# #4.方法一结束

#5.方法二，需要自己组装raw_data_protobuf,直接对交易的rawdata进行转十六进制进行hash，对hash结果转十六进制字符串得到txID，对hash结果进行签名即为对交易进行签名
#5.1 根据protobuf协议生成constact数据
rawdata_constact_parameter_value_hex_protbuf = []
def str2hex(strIN):
    outhex = []
    leng = len(strIN)
    if leng % 2 != 0:
        strIN = "0" + strIN
        leng = leng + 1
    for i in range(0, leng, 2):
        temp = ord(strIN[i])
        if temp >= 0x30 and temp <= 0x39:
            temp = temp - 0x30
        elif temp >= 0x61 and temp <= 0x66:
            temp = temp - 0x61 + 10

        temp1 = ord(strIN[i + 1])
        if temp1 >= 0x30 and temp1 <= 0x39:
            temp1 = temp1 - 0x30
        elif temp1 >= 0x61 and temp1 <= 0x66:
            temp1 = temp1 - 0x61 + 10

        temp = (temp << 4) | temp1
        if temp > 0x80:
            temp = temp - 1
            temp = (~temp) & 0xFF
            temp = 0 - temp
        outhex.append(temp)
    return outhex

owner_address_hex_data = str2hex(owner_address_hex)
filenum = 1
wiretype = 0x2
owner_address_hex_data_probuf = []
owner_address_hex_data_probuf.append(filenum << 3 | wiretype)
owner_address_hex_data_probuf.append(len(owner_address_hex_data))
owner_address_hex_data_probuf.extend(owner_address_hex_data)

to_address_hex_data = str2hex(to_address_hex)
filenum = 2
wiretype = 0x2
to_address_hex_data_probuf = []
to_address_hex_data_probuf.append(filenum << 3 | wiretype)
to_address_hex_data_probuf.append(len(to_address_hex_data))
to_address_hex_data_probuf.extend(to_address_hex_data)

filenum = 3
wiretype = 0
amount_probuf = []
amount_probuf.append(filenum << 3 | wiretype)
while True:
    if amount > 0x7F:
        temp = amount & 0x7F | 0x80
        if temp > 0x7F:
            temp = temp - 1
            temp = (~temp) & 0xFF
            temp = 0 - temp
        else:
            temp = 0 -temp
        amount_probuf.append(temp)
        amount = amount >>7
    else:
        amount_probuf.append(amount)
        break

rawdata_constact_parameter_value_hex_protbuf.extend(owner_address_hex_data_probuf)
rawdata_constact_parameter_value_hex_protbuf.extend(to_address_hex_data_probuf)
rawdata_constact_parameter_value_hex_protbuf.extend(amount_probuf)

# 根据protobuf协议生成raw_data_protobuf数据
raw_data_protobuf = []

ref_block_bytes_hex = str2hex(ref_block_bytes)
filenum = 1
wiretype = 0x2
raw_data_protobuf.append(filenum << 3 | wiretype)
raw_data_protobuf.append(len(ref_block_bytes_hex))
raw_data_protobuf.extend(ref_block_bytes_hex)

ref_block_hash_hex = str2hex(ref_block_hash)
filenum = 4
wiretype = 0x2
raw_data_protobuf.append(filenum << 3 | wiretype)
raw_data_protobuf.append(len(ref_block_hash_hex))
raw_data_protobuf.extend(ref_block_hash_hex)

filenum = 8
wiretype = 0
expiration_probuf = []
while True:
    if expiration > 0x7F:
        temp = expiration & 0x7F | 0x80
        if temp > 0x7F:
            temp = temp - 1
            temp = (~temp) & 0xFF
            temp = 0 - temp
        else:
            temp = 0 -temp
        expiration_probuf.append(temp)
        expiration = expiration >>7
    else:
        expiration_probuf.append(expiration)
        break
raw_data_protobuf.append(filenum << 3 | wiretype)
raw_data_protobuf.extend(expiration_probuf)

####组装rawdata_constact_protobuf数据
raw_data_contract_type_protobuf = []
filenum = 1
wiretype = 0
_type = ContractType.TransferContract.value
raw_data_contract_type_protobuf.append(filenum << 3 | wiretype)
raw_data_contract_type_protobuf.append(_type)

raw_data_contract_parameter_typeurl_protobuf = []
filenum = 1
wiretype = 2
length = len(type_url)
raw_data_contract_parameter_typeurl_protobuf.append(filenum << 3 | wiretype)
raw_data_contract_parameter_typeurl_protobuf.append(length)
raw_data_contract_parameter_typeurl_protobuf.extend(type_url_hex)

rawdata_constact_parameter_value_protbuf = []
filenum = 2
wiretype = 2
rawdata_constact_parameter_value_protbuf.append(filenum << 3 | wiretype)
rawdata_constact_parameter_value_protbuf.append(len(rawdata_constact_parameter_value_hex_protbuf))
rawdata_constact_parameter_value_protbuf.extend(rawdata_constact_parameter_value_hex_protbuf)

rawdata_constact_parameter_protbuf = []
filenum = 2
wiretype = 2
rawdata_constact_parameter_protbuf.append(filenum << 3 | wiretype)
rawdata_constact_parameter_protbuf.append(len(raw_data_contract_parameter_typeurl_protobuf) + len(rawdata_constact_parameter_value_protbuf))
rawdata_constact_parameter_protbuf.extend(raw_data_contract_parameter_typeurl_protobuf)
rawdata_constact_parameter_protbuf.extend(rawdata_constact_parameter_value_protbuf)

rawdata_constact_protbuf = []
filenum = 11
wiretype = 2
rawdata_constact_protbuf.append(filenum << 3 | wiretype)
rawdata_constact_protbuf.append(len(raw_data_contract_type_protobuf) + len(rawdata_constact_parameter_protbuf))
rawdata_constact_protbuf.extend(raw_data_contract_type_protobuf)
rawdata_constact_protbuf.extend(rawdata_constact_parameter_protbuf)
####组装rawdata_constact_protobuf数据结束

raw_data_protobuf.extend(rawdata_constact_protbuf)

filenum = 14
wiretype = 0
timestamp_probuf = []
while True:
    if timestamp > 0x7F:
        temp = timestamp & 0x7F | 0x80
        if temp > 0x7F:
            temp = temp - 1
            temp = (~temp) & 0xFF
            temp = 0 - temp
        else:
            temp = 0 -temp
        timestamp_probuf.append(temp)
        timestamp = timestamp >>7
    else:
        timestamp_probuf.append(timestamp)
        break
raw_data_protobuf.append(filenum << 3 | wiretype)
raw_data_protobuf.extend(timestamp_probuf)

for i in range(len(raw_data_protobuf)):    #注意一定要转换成字节数组，保证每个元素是0到255之间
    if raw_data_protobuf[i] < 0:
        raw_data_protobuf[i] = 256 + raw_data_protobuf[i]
#组装raw_data_protobuf结束

# #6. 方法二（一）开始
# def keccak256(data):
#     hasher = keccak.new(digest_bits=256)
#     hasher.update(data)
#     return hasher.digest()
#
# def verifying_key_to_addr(key):
#     pub_key = key.to_string()
#     primitive_addr = b'\x41' + keccak256(pub_key)[-20:]
#     addr = base58.b58encode_check(primitive_addr)
#     return addr
#
# print("=> my addr key")
# raw_priv_key = bytes.fromhex(private_key_string)
#
# priv_key = ecdsa.SigningKey.from_string(raw_priv_key, curve=ecdsa.SECP256k1)
# pub_key = priv_key.get_verifying_key().to_string()
# print('Pub Key:', pub_key.hex())
#
# primitive_addr = b'\x41' + keccak256(pub_key)[-20:]
# addr = base58.b58encode_check(primitive_addr)
# print('My Addr:', addr)
#
# raw_data_protobuf_str = ""
# for i in range(len(raw_data_protobuf)):
#     if raw_data_protobuf[i] > 0xF:
#         strtemp = str(hex(raw_data_protobuf[i]))[2:]
#     elif raw_data_protobuf[i] < 0:
#         if raw_data_protobuf[i] < -0xF:
#             strtemp = str(hex(raw_data_protobuf[i]))[3:]
#         else:
#             strtemp = "0" + str(hex(raw_data_protobuf[i]))[3:]
#     else:
#         strtemp = "0" + str(hex(raw_data_protobuf[i]))[2:]
#     raw_data_protobuf_str = raw_data_protobuf_str + strtemp
#     len_raw_data_protobuf_str = len(raw_data_protobuf_str)
# print(raw_data_protobuf_str)
# raw_data = bytes.fromhex(raw_data_protobuf_str)
# signature_temp = priv_key.sign_deterministic(raw_data, hashfunc=hashlib.sha256)
#
# # recover address to get rec_id
# pub_keys = ecdsa.VerifyingKey.from_public_key_recovery(
#     signature_temp[:64], raw_data, curve=ecdsa.SECP256k1, hashfunc=hashlib.sha256
# )
# for v, pk in enumerate(pub_keys):
#     if verifying_key_to_addr(pk) == addr:
#         break
#
# signature_temp += bytes([v])
# signature_temp_hex = (signature_temp.hex())
# signature.append(signature_temp_hex)
# #6.方法二（一）结束


#7.方法二（二）开始
#7.1 进行hash
raw_data_protobuf_str = ""
for i in range(len(raw_data_protobuf)):
    if raw_data_protobuf[i] > 0xF:
        strtemp = str(hex(raw_data_protobuf[i]))[2:]
    elif raw_data_protobuf[i] < 0:
        if raw_data_protobuf[i] < -0xF:
            strtemp = str(hex(raw_data_protobuf[i]))[3:]
        else:
            strtemp = "0" + str(hex(raw_data_protobuf[i]))[3:]
    else:
        strtemp = "0" + str(hex(raw_data_protobuf[i]))[2:]
    raw_data_protobuf_str = raw_data_protobuf_str + strtemp
    len_raw_data_protobuf_str = len(raw_data_protobuf_str)
print(raw_data_protobuf_str)
raw_data_str = bytes.fromhex(raw_data_protobuf_str)
hash_result = hashlib.sha256()
hash_result.update(raw_data_str)
hash_result_y = (hash_result.digest())
hash_r = []
for i in range(len(hash_result_y)):
    hash_r.append(hash_result_y[i])

#7.2 获取txID
txID_self = ""
for i in range(len(hash_r)):
    if hash_r[i] > 0xF:
        strtemp = str(hex(hash_r[i]))[2:]
    else:
        strtemp = "0" + str(hex(hash_r[i]))[2:]
    txID_self = txID_self + strtemp
transcation["txID"] = txID_self

#7.3 对交易进行签字
sig_self = private_key.sign_msg_hash(bytes(hash_r))
signature.append(sig_self.hex())
#方法二（二）结束

#8.对交易进行广播
result_broadcast = provider.make_request("/wallet/broadcasttransaction", transcation)

pprint(transcation)
print("createTranscation End！！！")
