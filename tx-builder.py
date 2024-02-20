from ast import List
import binascii
from hashlib import sha256, new
import hashlib
import base58
from ecdsa import SigningKey, SECP256k1, util
from subprocess import CalledProcessError, run

import ecdsa


def sign(priv: bytes, msg: bytes) -> bytes:
    sk = SigningKey.from_string(priv, curve=SECP256k1)
    while True:
        signature_der = sk.sign_digest_deterministic(msg, hashfunc=hashlib.sha256, sigencode=util.sigencode_der)
        r, s = util.sigdecode_der(signature_der, SECP256k1.order)
        if s > SECP256k1.order // 2:
            s = SECP256k1.order - s
            signature_der = util.sigencode_der(r, s, SECP256k1.order)
        signature_with_sighash = signature_der + b'\x01'
        if s <= SECP256k1.order // 2:
            break
    return signature_with_sighash


def varint(n):
    if n < 0xfd:
        return n.to_bytes(1, "little")
    elif n <= 0xffff:
        return b'\xfd' + n.to_bytes(2, "little")
    elif n <= 0xffffffff:
        return b'\xfe' + n.to_bytes(4, "little")
    else:
        return b'\xff' + n.to_bytes(8, "little")


def get_txid(inputs: List[bytes], outputs: List[bytes]) -> str:
    version = (2).to_bytes(4, "little")
    locktime = bytes.fromhex("00000000")
    input_count = len(inputs).to_bytes(1, "little")
    output_count = len(outputs).to_bytes(1, "little")
    serialized_inputs = b''.join(inputs)
    serialized_outputs = b''.join(outputs)
    transaction = (version + input_count + serialized_inputs + output_count + serialized_outputs + locktime)
    hash = hashlib.sha256(hashlib.sha256(transaction).digest()).digest()
    txid = hash[::-1].hex()
    return txid

def generate_redeem_script(pre_image: str) -> str:
    """Generate the redeem script in hex format for a given pre-image."""
    pre_image_bytes = pre_image.encode()  # Convert string to byte representation
    hash_hex = sha256(pre_image_bytes).hexdigest()  # Calculate SHA-256 hash
    redeem_script = f"a8{hash_hex}87"  # Construct redeem script with OP_SHA256 and OP_EQUAL
    return redeem_script

def derive_p2sh_address(redeem_script: str) -> str:
    """Derive a P2SH address from the redeem script for the Bitcoin testnet."""
    script_sha256 = sha256(bytes.fromhex(redeem_script)).digest()
    script_hash = new('ripemd160', script_sha256).digest()
    version_byte = b'\xc4'  # Version byte for testnet
    versioned_script_hash = version_byte + script_hash
    checksum = sha256(sha256(versioned_script_hash).digest()).digest()[:4]
    address_bytes = versioned_script_hash + checksum
    p2sh_address = base58.b58encode(address_bytes).decode()
    return p2sh_address


def address_to_hash160(addr: str) -> bytes:
    """Convert a base58 P2SH address back to its hash160 form."""
    addr_payload = base58.b58decode(addr)
    hash160 = addr_payload[1:-4]  # Strip off version byte and checksum
    return hash160


def create_transaction_to_p2sh(p2sh_address, amount, prev_txid, prev_vout, priv_key):
    # Convert the private key from hex to a SigningKey object
    priv_key_bytes = bytes.fromhex(priv_key)
    signing_key = SigningKey.from_string(priv_key_bytes, curve=SECP256k1)
    
    # Construct the txin structure
    txid_bytes = bytes.fromhex(prev_txid)[::-1]  # TXID in little endian
    vout_bytes = prev_vout.to_bytes(4, 'little')
    sequence = 0xffffffff  # Sequence number, typically set to max value
    scriptSig = b''  # Initially empty; will be filled with the script that unlocks the previous output
    
    # Construct the txout structure
    scriptPubKey = hashlib.new('ripemd160', binascii.unhexlify(p2sh_address)).digest()
    scriptPubKey = b'\xa9' + (len(scriptPubKey)).to_bytes(1, 'little') + scriptPubKey + b'\x87'
    
    # Output value (amount to send)
    value_bytes = amount.to_bytes(8, 'little')
    
    # Version
    version = 1
    version_bytes = version.to_bytes(4, 'little')
    
    # Locktime
    locktime = 0
    locktime_bytes = locktime.to_bytes(4, 'little')
    
    # TXIN and TXOUT count
    txin_count = 1
    txout_count = 1
    
    # Construct raw transaction
    raw_tx = (
        version_bytes +
        txin_count.to_bytes(1, 'little') +
        txid_bytes +
        vout_bytes +
        (len(scriptSig)).to_bytes(1, 'little') +  # ScriptSig is empty for now
        sequence.to_bytes(4, 'little') +
        txout_count.to_bytes(1, 'little') +
        value_bytes +
        (len(scriptPubKey)).to_bytes(1, 'little') + scriptPubKey +
        locktime_bytes
    )
    
    # Sign the transaction
    sighash = hashlib.sha256(hashlib.sha256(raw_tx).digest()).digest()
    signature = signing_key.sign_digest(sighash, sigencode=ecdsa.util.sigencode_der) + b'\x01'  # Append SIGHASH_ALL
    scriptSig = signature  # In reality, scriptSig would also include the public key and possibly other scripts
    
    # Replace scriptSig length in raw_tx with actual length
    raw_tx_signed = (
        raw_tx[:41] +  # Up to scriptSig length
        (len(scriptSig)).to_bytes(1, 'little') +
        scriptSig +
        raw_tx[42 + len(scriptSig):]  # Sequence to the end
    )
    
    # Serialize and return the signed transaction
    serialized_tx = binascii.hexlify(raw_tx_signed).decode('utf-8')
    return serialized_tx
def bcli(cmd: str):
    res = run(
        ["bitcoin-cli"]
        + cmd.split(" "),
        capture_output=True,
        encoding="utf-8",
    )
    if res.returncode == 0:
        return res.stdout.strip()
    else:
        raise Exception(res.stderr.strip())
# Example usage
if __name__ == "__main__":
    pre_image = "Btrust Builders"
    redeem_script = generate_redeem_script(pre_image)
    print(f"Redeem Script: {redeem_script}")

    p2sh_address = derive_p2sh_address(redeem_script)
    print(f"P2SH Address: {p2sh_address}")

    # Placeholder values for transaction creation
    prev_tx_id = ""
    vout_index = 0
    privKey = ""
    create_transaction_to_p2sh(p2sh_address, 100000, prev_tx_id, vout_index, privKey)
