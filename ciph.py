# Secure File Sharing Tool with AES Encryption

import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import hashlib
import getpass

# Function to derive a key from a password
def derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashlib.sha256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return kdf.derive(password.encode())

# Encrypt the file
def encrypt_file(input_file: str, output_file: str, password: str):
    # Generate random salt and IV
    salt = os.urandom(16)
    iv = os.urandom(16)
    key = derive_key(password, salt)

    # Create cipher object
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    # Read the input file and pad the content
    with open(input_file, 'rb') as f:
        data = f.read()
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(data) + padder.finalize()

    # Write the encrypted content
    with open(output_file, 'wb') as f:
        f.write(salt + iv + encryptor.update(padded_data) + encryptor.finalize())
    print(f"File encrypted and saved as {output_file}")

# Decrypt the file
def decrypt_file(input_file: str, output_file: str, password: str):
    with open(input_file, 'rb') as f:
        salt = f.read(16)
        iv = f.read(16)
        encrypted_data = f.read()

    key = derive_key(password, salt)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_padded_data = decryptor.update(encrypted_data) + decryptor.finalize()

    # Remove padding
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    data = unpadder.update(decrypted_padded_data) + unpadder.finalize()

    with open(output_file, 'wb') as f:
        f.write(data)
    print(f"File decrypted and saved as {output_file}")

# Main function for command-line arguments
def main():
    import argparse
    parser = argparse.ArgumentParser(description="Secure File Sharing Tool with AES Encryption")
    parser.add_argument("mode", choices=["encrypt", "decrypt"], help="Mode: encrypt or decrypt the file")
    parser.add_argument("input_file", help="Input file path")
    parser.add_argument("output_file", help="Output file path")
    args = parser.parse_args()

    password = getpass.getpass(prompt="Enter password: ")

    if args.mode == "encrypt":
        encrypt_file(args.input_file, args.output_file, password)
    elif args.mode == "decrypt":
        decrypt_file(args.input_file, args.output_file, password)

if __name__ == "__main__":
    main()
