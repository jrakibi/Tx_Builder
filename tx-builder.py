import binascii
from hashlib import sha256, new as hashlib_new
import base58
from ecdsa import SigningKey, SECP256k1, util

def generate_redeem_script(pre_image: str) -> str:
    """
    Generate a redeem script for a given pre-image.
    The redeem script format follows: OP_SHA256 <hash_of_preimage> OP_EQUAL.
    """
    # Convert the pre-image from string to bytes
    pre_image_bytes = pre_image.encode()
    # Calculate the SHA-256 hash of the pre-image
    hash_hex = sha256(pre_image_bytes).hexdigest()
    # Construct the redeem script with OP_SHA256 + hash + OP_EQUAL
    redeem_script = f"a8{hash_hex}87"
    return redeem_script

def derive_p2sh_address(redeem_script: str, testnet: bool = True) -> str:
    """
    Derive a P2SH address from the provided redeem script.
    The function supports both testnet and mainnet addresses.
    """
    # Hash the redeem script with SHA256, then RIPEMD-160
    script_sha256 = sha256(bytes.fromhex(redeem_script)).digest()
    script_hash = hashlib_new('ripemd160', script_sha256).digest()
    # Prefix with the version byte (testnet or mainnet)
    version_byte = b'\xc4' if testnet else b'\x05'
    # Combine the version byte with the script hash
    versioned_script_hash = version_byte + script_hash
    # Calculate the checksum by double hashing with SHA256
    checksum = sha256(sha256(versioned_script_hash).digest()).digest()[:4]
    # Concatenate versioned script hash and checksum
    address_bytes = versioned_script_hash + checksum
    # Encode the address in Base58Check format
    p2sh_address = base58.b58encode(address_bytes).decode()
    return p2sh_address

def sign(priv_key: bytes, msg: bytes) -> bytes:
    """
    Sign a message using the given private key.
    Returns the signature appended with SIGHASH_ALL byte.
    """
    # Initialize the signing key from the private key bytes
    sk = SigningKey.from_string(priv_key, curve=SECP256k1)
    # Sign the message deterministically with SHA256
    signature = sk.sign_digest_deterministic(msg, hashfunc=sha256, sigencode=util.sigencode_der_canonize)
    # Append SIGHASH_ALL to indicate the signature applies to all inputs
    return signature + b'\x01'

def sign_transaction(priv_key: bytes, transaction: bytes, redeem_script: str) -> bytes:
    """Sign a P2SH transaction input."""
    sk = SigningKey.from_string(priv_key, curve=SECP256k1)
    # Simplified: Append redeem script and SIGHASH_ALL for demonstration purposes
    tx_to_sign = transaction + bytes.fromhex(redeem_script) + b'\x01'
    sighash = sha256(sha256(tx_to_sign).digest()).digest()
    # Sign the sighash
    signature = sk.sign_digest_deterministic(sighash, hashfunc=sha256, sigencode=util.sigencode_der)
    return signature + b'\x01'  # Signature with SIGHASH_ALL


def create_transaction_to_p2sh(p2sh_address: str, amount: int, prev_txid: str, prev_vout: int, priv_key: str) -> str:
    """
    Create a transaction that sends bitcoins to a P2SH address.
    This function constructs the transaction but does not broadcast it.
    """
    # Decode the P2SH address from Base58Check format to get the binary data This includes the version byte, script hash, and checksum
    decoded_data = base58.b58decode_check(p2sh_address)

    # Extract the script hash from the decoded data
    # Skip the first byte (version byte) to get the script hash
    script_hash = decoded_data[1:]
    
    # The scriptPubKey for a P2SH output follows the pattern: OP_HASH160 <ScriptHash> OP_EQUAL
    # <ScriptHash> is the RIPEMD-160(SHA-256) hash of the redeem script, already encoded in the P2SH address
    # The length of the ScriptHash is prefixed to indicate the number of bytes to push onto the stack
    scriptPubKey = b'\xa9' + bytes([len(script_hash)]) + script_hash + b'\x87'

    # Prepare the transaction inputs (previous transaction ID and output index)
    txid_bytes = bytes.fromhex(prev_txid)[::-1]  # Convert txid to little endian
    vout_bytes = prev_vout.to_bytes(4, 'little')  # Convert output index to bytes
    sequence = bytes([0xff, 0xff, 0xff, 0xff])  # Set sequence to max value

    # Construct the transaction components
    version = bytes([0x01, 0x00, 0x00, 0x00])  # Transaction version
    txin_count = bytes([0x01])  # Number of transaction inputs
    txout_count = bytes([0x01])  # Number of transaction outputs
    locktime = bytes([0x00, 0x00, 0x00, 0x00])  # Transaction locktime
    value_bytes = amount.to_bytes(8, 'little')  # Amount to send

    # Create the raw transaction template
    raw_tx = (
        version +
        txin_count +
        txid_bytes +
        vout_bytes +
        bytes([0x00]) +  # Placeholder for scriptSig length
        sequence +
        txout_count +
        value_bytes +
        bytes([len(scriptPubKey)]) + scriptPubKey +
        locktime
    )


    # Sign the transaction
    priv_key_bytes = bytes.fromhex(priv_key)
    signature = sign_transaction(priv_key_bytes, raw_tx, redeem_script)

    # Construct scriptSig with the signature and the redeem script
    scriptSig = signature + bytes.fromhex(redeem_script)
    scriptSig_len = bytes([len(scriptSig)])
    raw_tx_signed = (
        version +
        txin_count +
        txid_bytes +
        vout_bytes +
        scriptSig_len + scriptSig +  # Insert the actual scriptSig
        sequence +
        txout_count +
        value_bytes +
        bytes([len(scriptPubKey)]) + scriptPubKey +
        locktime
    )

    return binascii.hexlify(raw_tx_signed).decode('utf-8')

# Example usage to demonstrate the functions
if __name__ == "__main__":
    pre_image = "Btrust Builders"
    redeem_script = generate_redeem_script(pre_image)
    print(f"Redeem Script: {redeem_script}")

    p2sh_address = derive_p2sh_address(redeem_script)
    print(f"P2SH Address: {p2sh_address}")

    # Placeholder values for transaction creation
    prev_tx_id = "your_previous_tx_id_here"  # Example: 'abcdef1234567890...'
    vout_index = 0  # Example output index you want to spend
    amount = 10000  # Amount to send in satoshis
    priv_key = "your_private_key_here"  # Example: '123abc456def7890...'

    tx_hex = create_transaction_to_p2sh(p2sh_address, amount, prev_tx_id, vout_index, priv_key)
    print(f"Transaction Hex: {tx_hex}")
