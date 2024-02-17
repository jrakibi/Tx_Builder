import hashlib
from subprocess import run
from ecdsa import SigningKey, SECP256k1, util
from typing import List
from balance import (
    EXTENDED_PRIVATE_KEY,
    bcli,
    get_pub_from_priv as derive_pub_key,
    get_p2wpkh_program as calculate_p2wpkh_program,
    recover_wallet_state as synchronize_wallet_data)

def generate_2of2_multisig_script(keys: List[bytes]) -> bytes:
    prefix_op_2 = b'\x52'
    pubkey_length = b'\x21'
    suffix_op_checkmultisig = b'\xae'
    script = prefix_op_2 + pubkey_length + keys[0] + pubkey_length + keys[1] + prefix_op_2 + suffix_op_checkmultisig
    return script

def calculate_p2wsh_program(script: bytes) -> bytes:
    sha256_digest = hashlib.sha256(script).digest()
    script_pubkey_prefix = b'\x00' + b'\x20'  # Version 0, push 32 bytes
    return script_pubkey_prefix + sha256_digest

def prepare_input_for_utxo(txid: bytes, index: int) -> bytes:
    txid_reversed = txid[::-1]
    index_bytes = index.to_bytes(4, byteorder='little')
    empty_scriptSig = b'\x00'
    sequence_numbers = b'\xff\xff\xff\xff'
    input_format = txid_reversed + index_bytes + empty_scriptSig + sequence_numbers
    return input_format

def create_output_for_script(script: bytes, amount: int) -> bytes:
    amount_bytes = amount.to_bytes(8, byteorder='little')
    script_length = len(script)
    script_length_bytes = script_length.to_bytes(1, byteorder='little') if script_length < 253 else b'\xfd' + script_length.to_bytes(2, byteorder='little')
    output_format = amount_bytes + script_length_bytes + script
    return output_format

def derive_p2wpkh_script_code(utxo_info: object) -> bytes:
    scriptPubKey_hex = utxo_info['scriptPubKey']
    scriptPubKey = bytes.fromhex(scriptPubKey_hex)
    if scriptPubKey.startswith(bytes.fromhex('0014')):
        pubkey_hash = scriptPubKey[2:]
        script_code = bytes.fromhex('1976a914') + pubkey_hash + bytes.fromhex('88ac')
        return script_code
    else:
        raise ValueError("Unsupported P2WPKH scriptPubKey format")

def calculate_transaction_hash(outpoint: bytes, script_code: bytes, amount: int, output_list: List[bytes]) -> bytes:
    def double_sha256(data: bytes) -> bytes:
        return hashlib.sha256(hashlib.sha256(data).digest()).digest()
    version_info = (2).to_bytes(4, byteorder='little')
    hash_prevouts = double_sha256(outpoint)
    sequence_bytes = (0xffffffff).to_bytes(4, byteorder='little')
    hash_sequence = double_sha256(sequence_bytes)
    amount_bytes = amount.to_bytes(8, byteorder='little')
    all_outputs = b''.join(output_list)
    hash_outputs = double_sha256(all_outputs)
    locktime_info = (0).to_bytes(4, byteorder='little')
    sighash_flag = (1).to_bytes(4, byteorder='little')
    signing_preimage = version_info + hash_prevouts + hash_sequence + outpoint + script_code + amount_bytes + sequence_bytes + hash_outputs + locktime_info + sighash_flag
    transaction_hash = double_sha256(signing_preimage)
    return transaction_hash

def produce_signature(private_key: bytes, message: bytes) -> bytes:
    sk = SigningKey.from_string(private_key, curve=SECP256k1)
    while True:
        signature_der = sk.sign_digest_deterministic(message, hashfunc=hashlib.sha256, sigencode=util.sigencode_der)
        r, s = util.sigdecode_der(signature_der, SECP256k1.order)
        if s > SECP256k1.order // 2:
            s = SECP256k1.order - s
            signature_der = util.sigencode_der(r, s, SECP256k1.order)
        signature_with_type = signature_der + b'\x01'
        if s <= SECP256k1.order // 2:
            break
    return signature_with_type

def compile_p2wpkh_witness(private_key: bytes, message: bytes) -> bytes:
    signature_with_type = produce_signature(private_key, message)
    compressed_pub_key = derive_pub_key(private_key)
    witness_count = bytes([2])
    signature_length = bytes([len(signature_with_type)])
    pub_key_length = bytes([len(compressed_pub_key)])
    witness_compilation = witness_count + signature_length + signature_with_type + pub_key_length + compressed_pub_key
    return witness_compilation

def construct_p2wsh_witness(private_keys: List[bytes], message: bytes) -> bytes:
    signatures = [produce_signature(priv, message) for priv in private_keys]
    witness_buffer = b''
    for signature in signatures:
        witness_buffer += len(signature).to_bytes(1, "little") + signature
    multisig_script = generate_2of2_multisig_script([derive_pub_key(priv) for priv in private_keys])
    multisig_script_length = len(multisig_script).to_bytes(1, "little")
    witness_buffer += multisig_script_length + multisig_script
    return witness_buffer

def build_transaction(inputs: List[bytes], outputs: List[bytes], witness_data: List[bytes]) -> str:
    version = (2).to_bytes(4, "little")
    marker_and_flag = bytes.fromhex("0001")
    input_count = len(inputs).to_bytes(1, "little")
    output_count = len(outputs).to_bytes(1, "little")
    transaction_body = version + marker_and_flag + input_count + b''.join(inputs) + output_count + b''.join(outputs) + b''.join(witness_data) + bytes.fromhex("00000000")
    return transaction_body.hex()

def calculate_txid(inputs: List[bytes], outputs: List[bytes]) -> str:
    version = (2).to_bytes(4, "little")
    locktime = bytes.fromhex("00000000")
    input_counter = len(inputs).to_bytes(1, "little")
    output_counter = len(outputs).to_bytes(1, "little")
    transaction_components = version + input_counter + b''.join(inputs) + output_counter + b''.join(outputs) + locktime
    transaction_hash = hashlib.sha256(hashlib.sha256(transaction_components).digest()).digest()
    txid = transaction_hash[::-1].hex()
    return txid

# The rest of the code, including `spend_p2wpkh` and `spend_p2wsh` functions, should be updated accordingly to use these new method names.
