from decimal import Decimal
from ecdsa import SigningKey, SECP256k1
from subprocess import CalledProcessError, run
from typing import List, Tuple
import hashlib
import hmac
import json

# Provided by administrator
WALLET_NAME = "wallet_057"
EXTENDED_PRIVATE_KEY = "tprv8ZgxMBicQKsPcxw2kWMFYjp6f3ttLag5qNAmUNtbgqG1vVY8sDLFqfe4eFMrSjSg1YZu83XtRc3DMnt4q9qZiD4pAtbhAt3KjB5ny6oY69C"

def decode_base58(base58_string: str) -> bytes:
    base58_alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    num = 0
    for char in base58_string:
        num = num * 58 + base58_alphabet.index(char)
    byte_array = bytearray()
    while num > 0:
        byte_array.append(num % 256)
        num //= 256
    byte_array.reverse()
    payload, checksum = byte_array[:-4], byte_array[-4:]
    calculated_checksum = hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
    if calculated_checksum != checksum:
        raise ValueError("Invalid checksum for base58 string.")
    return payload

def key_deserializer(b: bytes) -> object:
    if len(b) != 78:
        raise ValueError("Invalid length")
    version = b[:4].hex()
    depth = hex(b[4])[2:]
    parent_fingerprint = b[5:9].hex()
    child_number = b[9:13].hex()
    chain_code = b[13:45].hex()
    key_data = b[45:][1:]
    return {"version": version, "depth": depth, "parent_fingerprint": parent_fingerprint, 
            "child_number": child_number, "chain_code": chain_code, "key_data": key_data.hex()}

def derive_compressed_pub(priv: bytes) -> bytes:
    sk = SigningKey.from_string(priv, curve=SECP256k1)
    vk = sk.verifying_key
    compressed_pubkey = vk.to_string("compressed")
    return compressed_pubkey

def generate_child_priv_key(key: bytes, chaincode: bytes, index: int, hardened: bool) -> object:
    if hardened:
        index += 0x80000000
    data = (b"\x00" + key if hardened else derive_compressed_pub(key)) + index.to_bytes(4, "big")
    hmac_result = hmac.new(chaincode, data, hashlib.sha512).digest()
    child_key = (int.from_bytes(key, "big") + int.from_bytes(hmac_result[:32], "big")) % SECP256k1.order
    return {"key": child_key.to_bytes(32, "big"), "chaincode": hmac_result[32:]}

def compute_wallet_priv_keys(key: bytes, chaincode: bytes, path: List[Tuple[int, bool]]) -> List[bytes]:
    for index, hardened in path:
        child_key_info = generate_child_priv_key(key, chaincode, index, hardened)
        key, chaincode = child_key_info["key"], child_key_info["chaincode"]
    return [generate_child_priv_key(key, chaincode, i, False)["key"] for i in range(2000)]

def construct_p2wpkh_witness_pubkey(pubkey: bytes, version: int = 0) -> bytes:
    return bytes([version, 0x14]) + hashlib.new("ripemd160", hashlib.sha256(pubkey).digest()).digest()

def bitcoin_cli_interface(cmd: str):
    res = run(
        ["bitcoin-cli", "-regtest"]
        + cmd.split(" "),
        capture_output=True,
        encoding="utf-8",
    )
    if res.returncode == 0:
        return res.stdout.strip()
    else:
        raise Exception(res.stderr.strip())

def synchronize_wallet(tprv: str):
    extended_key_bytes = decode_base58(tprv)
    key_info = key_deserializer(extended_key_bytes)
    priv_key = bytes.fromhex(key_info["key_data"])
    chain_code = bytes.fromhex(key_info["chain_code"])
    bip84_path = [(84, True), (1, True), (0, True), (0, False)]
    privs = compute_wallet_priv_keys(priv_key, chain_code, bip84_path)
    pubs = [derive_compressed_pub(priv) for priv in privs]
    programs = [construct_p2wpkh_witness_pubkey(pub) for pub in pubs]
    state = {"utxo": {}, "balance": Decimal('0'), "privs": privs, "pubs": pubs, "programs": programs}
    height = 310
    for h in range(height + 1):
        block_hash = bitcoin_cli_interface(f"getblockhash {h}")
        block = json.loads(bitcoin_cli_interface(f"getblock {block_hash} 2"))
        for tx in block["tx"]:
            txid = tx["txid"]
            for idx, out in enumerate(tx["vout"]):
                scriptPubKey = bytes.fromhex(out["scriptPubKey"]["hex"])
                if scriptPubKey in programs:
                    value_sats = Decimal(out["value"]) * Decimal(1e8)
                    state["balance"] += value_sats
                    state["utxo"][f"{txid}:{idx}"] = {"value": value_sats, "scriptPubKey": scriptPubKey.hex()}
            for inp in tx["vin"]:
                if "txinwitness" in inp and len(inp["txinwitness"]) > 1:
                    compressed_pubkey = bytes.fromhex(inp["txinwitness"][1])
                    if compressed_pubkey in pubs:
                        outpoint = f"{inp['txid']}:{inp['vout']}"
                        if outpoint in state["utxo"]:
                            state["balance"] -= state["utxo"][outpoint]["value"]
                            del state["utxo"][outpoint]
    return state

if __name__ == "__main__":
    state = synchronize_wallet(EXTENDED_PRIVATE_KEY)
    balance_btc = state["balance"] / Decimal('1e8')
    print(f"{WALLET_NAME} {balance_btc:.8f}")
