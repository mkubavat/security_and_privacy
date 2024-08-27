import os
import sys
from subprocess import check_output

def decrypt_byte(ciphertext, y_n_minus_1):
    y_n = ciphertext[-16:]  # Last block as y_N

    # Start with i = 0
    for i in range(256):
        r = os.urandom(15) + bytes([i])
        # Create modified ciphertext (r | y_n)
        modified_ciphertext = r + y_n  # Do not include IV when sending to oracle
        # Save this to a temporary file to pass to the oracle
        with open("temp_cipher.bin", "wb") as f:
            f.write(modified_ciphertext)
        
        # Call the oracle and check if padding is valid
        result = check_output(['python3', 'oracle.py', 'temp_cipher.bin']).strip()
        if result == b'1':  # If padding is correct
            d_y_n_16 = i ^ 0x01  # Calculate decrypted value with padding length 1
            x_n_16 = d_y_n_16 ^ y_n_minus_1[-1]
            return x_n_16

    raise Exception("Failed to decrypt the byte using the padding oracle")


def decrypt_block(ciphertext, y_n_minus_1):
    y_n = ciphertext[-16:]  # Last block as y_N

    # Start with decryption of the last byte
    decrypted_bytes = bytearray(16)
    derived_values = bytearray(16)

    # Initialize padding calculation
    padding_value = 17

    # Decrypt from the last byte to the first
    for k in range(15, -1, -1):
        padding_value -= 1
        for i in range(256):
            padding = bytes([(derived_values[j] ^ padding_value) for j in range(k+1, 16)])
            r = os.urandom(k) + bytes([i]) + padding
            modified_ciphertext = r + y_n  # Do not include IV when sending to oracle
            with open("temp_cipher.bin", "wb") as f:
                f.write(modified_ciphertext)
            result = check_output(['python3', 'oracle.py', 'temp_cipher.bin']).strip()
            
            if result == b'1':
                derived_values[k] = i
                decrypted_bytes[k] = derived_values[k] ^ y_n_minus_1[k]
                break

    return decrypted_bytes



def decrypt(ciphertext):
    iv = ciphertext[:16]
    blocks = [ciphertext[i:i+16] for i in range(16, len(ciphertext), 16)]

    plaintext = bytearray()

    # Decrypt from the last block to the first block
    for i in reversed(range(len(blocks))):
        if i == 0:
            previous_block = iv
        else:
            previous_block = blocks[i-1]
        
        decrypted_block = decrypt_block(blocks[i] + previous_block, previous_block)
        plaintext[0:0] = decrypted_block 

    pad_len = plaintext[-1]
    if pad_len < 1 or pad_len > 16:
        raise ValueError("Invalid padding length.")
    if all(plaintext[-j] == pad_len for j in range(1, pad_len+1)):
        return plaintext[:-pad_len]
    else:
        raise ValueError("Padding does not match expected format.")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python3 decrypt.py <ciphertext file>")
        sys.exit(1)
    
    with open(sys.argv[1], "rb") as file:
        ciphertext = file.read()
    
    if len(ciphertext) % 16 != 0 or len(ciphertext) < 32:
        print("Ciphertext must be a multiple of 16 bytes and at least 32 bytes.")
        sys.exit(1)
    
    try:
        plaintext = decrypt(ciphertext)
        plaintext_decoded = plaintext.decode('ascii')  # Decode bytes to string for ASCII plaintext

        # Now, write the decrypted plaintext to a file
        with open("plaintext.txt", "w") as text_file:
            text_file.write(plaintext_decoded)
        print("Decrypted plaintext saved to plaintext.txt")
    except ValueError as e:
        print(str(e))