from hashlib import sha256, new
import base58

def generate_redeem_script(pre_image: str) -> str:
    """Generate the redeem script in hex format for a given pre-image."""
    pre_image_bytes = pre_image.encode()  # Convert string to its byte representation
    hash_hex = sha256(pre_image_bytes).hexdigest()  # Calculate SHA-256 hash
    redeem_script = f"a8{hash_hex}87"  # Construct the redeem script with OP_SHA256 and OP_EQUAL
    return redeem_script

def derive_p2sh_address(redeem_script: str) -> str:
    """Derive a P2SH address from the redeem script."""
    script_sha256 = sha256(bytes.fromhex(redeem_script)).digest()
    script_hash = new('ripemd160', script_sha256).digest()
    version_byte = b'\x05'  # Version byte for mainnet
    versioned_script_hash = version_byte + script_hash
    checksum = sha256(sha256(versioned_script_hash).digest()).digest()[:4]
    address_bytes = versioned_script_hash + checksum
    p2sh_address = base58.b58encode(address_bytes).decode()
    return p2sh_address

# Example usage:
if __name__ == "__main__":
    # Step 1: Generate the redeem script
    pre_image = "Btrust Builders"
    redeem_script = generate_redeem_script(pre_image)
    print(f"Redeem Script: {redeem_script}")

    # Step 2: Derive P2SH address from the redeem script
    p2sh_address = derive_p2sh_address(redeem_script)
    print(f"P2SH Address: {p2sh_address}")
