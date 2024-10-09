# Secure File Sharing Tool with AES Encryption

## Introduction
This tool allows users to securely share files using AES (Advanced Encryption Standard) encryption. It provides a command-line interface to encrypt and decrypt files with a password, ensuring the confidentiality of sensitive information during file transfer. This project is useful for veterans or security professionals needing to share sensitive information securely.

## Features
- **AES Encryption (CBC Mode)**: Ensures secure encryption of files using a user-provided password.
- **Password-Based Key Derivation**: Uses PBKDF2 to derive a secure key from the password.
- **Command-Line Interface**: Allows users to easily encrypt or decrypt files via terminal commands.

## Requirements
- Python 3.x
- `cryptography` library

To install the required library, run:
```sh
pip install cryptography
```

## Usage
### Command-Line Arguments
- **mode**: Specify whether to `encrypt` or `decrypt` a file.
- **input_file**: Path to the input file to be encrypted or decrypted.
- **output_file**: Path to save the output (encrypted or decrypted) file.

### Example Commands
#### Encrypt a File
```sh
python secure_file_sharing_tool.py encrypt path/to/input_file.txt path/to/output_file.enc
```
You will be prompted to enter a password. The tool will encrypt the input file and save it as the output file.

#### Decrypt a File
```sh
python secure_file_sharing_tool.py decrypt path/to/input_file.enc path/to/output_file.txt
```
You will be prompted to enter the password used during encryption. The tool will decrypt the input file and save it as the output file.

## Important Notes
- **Password Security**: Ensure you use a strong password for encryption. The same password must be used to decrypt the file.
- **File Safety**: This tool does not store passwords or keys. Losing the password means losing access to the encrypted content.

## Disclaimer
This tool is intended for educational purposes and should be used responsibly. Always ensure you have permission to encrypt or decrypt files, and never use it for unauthorized purposes.

## License
MIT License
