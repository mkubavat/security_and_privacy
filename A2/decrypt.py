import subprocess
import sys

# Toggle this to False to reduce output verbosity
DEBUG = True

def debug_print(*args, **kwargs):
    if DEBUG:
        print(*args, **kwargs)

def run_oracle(ciphertext):
    # Save the modified ciphertext to a temporary file
    with open('temp_cipher.bin', 'wb') as f:
        f.write(ciphertext)

    try:
        # Call the oracle and capture the printed output
        result = subprocess.run('python3 oracle.py temp_cipher.bin', shell=True, capture_output=True, text=True)
        print("STDOUT:", result.stdout)
        print("STDERR:", result.stderr)
        if result.stdout.strip() == '1':
            debug_print("padding match !!!!!!")
            return 1
        else:
            debug_print("padding error....")
            return 0
    except subprocess.CalledProcessError as e:
        print("Oracle subprocess failed:", e)
        return 0

def modify_ciphertext_for_guess(ciphertext, guess, index, block_size):
    modified_ciphertext = bytearray(ciphertext)
    padding_value = block_size - index
    # XOR the guessed value with the padding value and the byte at the corresponding position
    modified_ciphertext[-block_size + index] ^= guess ^ padding_value
    return bytes(modified_ciphertext)

def decrypt_block(ciphertext, block_size, oracle):
    if len(ciphertext) % block_size != 0:
        raise ValueError("Invalid ciphertext length")
    
    decrypted_block = [0] * block_size
    # Start decrypting from the last byte to the first byte in the block
    for index in range(block_size):
        found = False
        for guess in range(256):
            modified_ciphertext = modify_ciphertext_for_guess(ciphertext, guess, index, block_size)
            if oracle(modified_ciphertext):
                decrypted_block[-1 - index] = guess
                debug_print(f"Guessed byte: {guess} at position {-1 - index}")  # Debugging line
                found = True
                break
        if not found:
            debug_print(f"Failed to guess byte at position {-1 - index}")  # Debugging line
    return decrypted_block

def main():
    if len(sys.argv) != 2:
        print("Usage: python3 decrypt.py <ciphertext_file>")
        sys.exit(1)

    block_size = 16  # Block size for AES
    ciphertext_file = sys.argv[1]

    with open(ciphertext_file, 'rb') as f:
        ciphertext = f.read()

    # Assuming there's at least one block of data plus IV
    if len(ciphertext) < 2 * block_size:
        print("Ciphertext too short.")
        return

    # Decrypt the last block
    decrypted_text = decrypt_block(ciphertext[-2*block_size:], block_size, run_oracle)
    try:
        final_text = bytes(decrypted_text).decode('utf-8')
        with open('plaintext.txt', 'w', encoding='utf-8') as file:
            file.write(final_text)
        print("Decrypted text:", final_text)
    except UnicodeDecodeError:
        print("Failed to decode decrypted text. Here's the byte representation:")
        print(decrypted_text)

if __name__ == "__main__":
    main()