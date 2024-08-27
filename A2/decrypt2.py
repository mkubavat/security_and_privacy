import subprocess
import sys
import tempfile
import os

# Configuration and debugging toggle
DEBUG = True

def debug_print(*args, **kwargs):
    if DEBUG:
        print(*args, **kwargs)

def run_oracle(ciphertext):
    # Create a temporary file
    with tempfile.NamedTemporaryFile(delete=False) as temp_file:
        temp_file.write(ciphertext)
        temp_file.flush()  # Ensure all data is written
        try:
            # Call the oracle and capture the output
            result = subprocess.run(['python3', 'oracle.py', temp_file.name], capture_output=True, text=True)
            print("STDOUT:", result.stdout)
            print("STDERR:", result.stderr)
            return 1 if result.stdout.strip() == '1' else 0
        except subprocess.CalledProcessError as e:
            print("Oracle subprocess failed:", e)
            return 0
        finally:
            # Clean up the temporary file
            os.unlink(temp_file.name)

def modify_ciphertext_for_guess(ciphertext, guess, index, block_size):
    modified_ciphertext = bytearray(ciphertext)
    padding_value = block_size - index
    # Adjust all bytes that need to reflect the padding value
    for i in range(1, padding_value):
        modified_ciphertext[-i] ^= padding_value
    modified_ciphertext[-padding_value] ^= guess ^ padding_value
    return bytes(modified_ciphertext)

def decrypt_block(ciphertext, block_size, oracle):
    if len(ciphertext) % block_size != 0:
        raise ValueError("Invalid ciphertext length")

    decrypted_block = [0] * block_size
    for index in range(block_size):
        found = False
        for guess in range(256):
            modified_ciphertext = modify_ciphertext_for_guess(ciphertext, guess, index, block_size)
            if oracle(modified_ciphertext):
                decrypted_block[-1 - index] = guess
                debug_print(f"Guessed byte: {guess} at position {-1 - index}")
                found = True
                break
        if not found:
            debug_print(f"Failed to guess byte at position {-1 - index}")
    return decrypted_block

def main():
    if len(sys.argv) != 2:
        print("Usage: python3 decrypt.py <ciphertext_file>")
        sys.exit(1)

    block_size = 16
    with open(sys.argv[1], 'rb') as f:
        ciphertext = f.read()

    if len(ciphertext) < 2 * block_size:
        print("Ciphertext too short.")
        return

    decrypted_text = decrypt_block(ciphertext[-2*block_size:], block_size, run_oracle)
    try:
        final_text = bytes(decrypted_text).decode('utf-8')
        with open('plaintext.txt', 'w', encoding='utf-8') as file:
            file.write(final_text)
        print("Decrypted text:", final_text)
    except UnicodeDecodeError:
        print("Failed to decode decrypted text. Here's the byte representation:", decrypted_text)

if __name__ == "__main__":
    main()
