import subprocess
import sys

def call_oracle(ciphertext):
    """Call the oracle.py with the given ciphertext and return whether the padding is valid."""
    try:
        # Oracle needs the ciphertext written to a file; modify this if the oracle reads from stdin
        with open('temp_ciphertext', 'wb') as f:
            f.write(ciphertext)
        # Call the oracle and capture output
        result = subprocess.check_output(['python3', 'oracle.py', 'temp_ciphertext'])
        return result.strip() == b'1'
    except subprocess.CalledProcessError as e:
        print("Oracle error:", e)
        return False

def modify_ciphertext(ciphertext, block_index, new_byte, position):
    """Return a modified version of the ciphertext at the specified block and position."""
    blocks = [ciphertext[i:i+16] for i in range(0, len(ciphertext), 16)]
    modified_block = bytearray(blocks[block_index])
    modified_block[position] = new_byte
    blocks[block_index] = bytes(modified_block)
    return b''.join(blocks)

def decrypt_byte(ciphertext, block_index, byte_index):
    """
    Decrypt a single byte by manipulating the preceding block to create valid padding.
    
    :param ciphertext: the complete ciphertext as a byte array
    :param block_index: the index of the block that contains the byte to decrypt
    :param byte_index: the index of the byte in its block to decrypt
    :return: decrypted byte or None if not found
    """
    if block_index == 0:
        raise ValueError("Cannot decrypt the first block with this method")

    # The block to modify to affect the target byte's padding
    preceding_block_index = block_index - 1

    # Make a copy of the ciphertext to modify
    modified_ciphertext = bytearray(ciphertext)

    # Initialize the byte we will change
    original_byte = modified_ciphertext[preceding_block_index * 16 + byte_index]

    for i in range(256):
        modified_ciphertext[preceding_block_index * 16 + byte_index] = i
        if call_oracle(bytes(modified_ciphertext)):
            # Padding is correct, calculate the plaintext byte
            decrypted_byte = i ^ (16 - byte_index) ^ original_byte
            return decrypted_byte

    return None  # if no valid padding found

def decrypt_block(ciphertext, block_index):
    if block_index == 0:
        raise ValueError("Cannot decrypt the first block directly with padding oracle attack")

    decrypted_block = []
    # Work backward from the last byte to the first byte of the block
    for byte_index in reversed(range(16)):
        decrypted_byte = decrypt_byte(ciphertext, block_index, byte_index)
        decrypted_block.insert(0, decrypted_byte)
        
        # Update the ciphertext to set up correct padding for the next byte
        for j in range(byte_index, 16):
            position = (block_index - 1) * 16 + j
            ciphertext[position] ^= (16 - byte_index) ^ (16 - byte_index + 1)

    return decrypted_block



def main(ciphertext_file):
    # Read the ciphertext from a file and convert it to a mutable bytearray
    with open(ciphertext_file, 'rb') as f:
        ciphertext = bytearray(f.read())  # Ensure it's a bytearray

    num_blocks = len(ciphertext) // 16
    decrypted_text = []

    # Decrypt each block starting from the last
    for block_index in range(num_blocks - 1, 0, -1):  # Skip the first block (IV)
        decrypted_block = decrypt_block(ciphertext, block_index)
        decrypted_text = decrypted_block + decrypted_text

    # Convert decrypted bytes to string (considering ASCII encoding)
    decrypted_message = bytes(decrypted_text).decode('ascii')
    print("Decrypted message:", decrypted_message)

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python3 decrypt.py <ciphertext_file>")
        sys.exit(1)
    main(sys.argv[1])
