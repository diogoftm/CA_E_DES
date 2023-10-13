from Crypto.Cipher import DES
from Crypto.Protocol.KDF import PBKDF2
import base64
import hashlib
import sys

from EDES import EDES

# Base64 encode


def base64Decode(data: bytes) -> bytes:
    return base64.b64decode(data)

# Derive key and iv from password, matching cpp EVP_BytesToKey


def deriveKey(passphrase: str, salt: bytes, key_len: int) -> bytes:
    iterations: int = 1  # Equivalent to the "1" argument in EVP_BytesToKey

    # Concatenate the password and salt
    data: bytes = passphrase.encode() + salt

    # Perform SHA-1 hashing for the given number of iterations
    for _ in range(iterations):
        data = hashlib.sha256(data).digest()

    # Take the first 8 bytes as the key
    key: bytes = data[:key_len]

    return key

# Encrypt using pycryptodome DES


def des_decrypt(ciphertext: bytes, key: bytes) -> bytes:
    cipher = DES.new(key, DES.MODE_ECB)
    plaintext: bytes = cipher.decrypt(ciphertext)
    return plaintext

# Decrypt using E-DES


def edes_decrypt(plaintext: bytes, key: bytes) -> bytes:
    edes = EDES()
    edes.set_key(key)
    return edes.decrypt(plaintext)

# Remove PKCS#7 pad


def remove_pkcs7_padding(data):
    padding_value = data[-1]
    if padding_value < 1 or padding_value > len(data):
        raise ValueError("Invalid PKCS#7 padding")
    return data[:-padding_value]


if __name__ == "__main__":
    standardDESFlag: bool = False

    # Check command line arguments
    if len(sys.argv) == 2:
        if sys.argv[1] == "-h":
            print("usage: python3 decrypt.py <password> <ciphertext> [-s]")
            sys.exit(0)
    else:
        if sys.argv[2] == "-s":
            standardDESFlag = True
        elif len(sys.argv) == 2:
            print("Invalid flag. Use -h for help.")
            sys.exit(1)
        else:
            print("Invalid number of arguments. Use -h for help.")
            sys.exit(1)

    password: str = sys.argv[1]
    ciphertext_base64: str = input()  # Read from stdin

    salt: bytes = bytes([0x01, 0x02, 0xFA, 0x00, 0x98, 0x11, 0x1D, 0xDD])
    # Derive key from password
    key = deriveKey(password, salt, 8 if standardDESFlag else 32)

    # Base 64 decode
    ciphertext: bytes = base64Decode(ciphertext_base64)

    # Decrypt
    if standardDESFlag:
        plaintext: bytes = des_decrypt(ciphertext, key)
    else:
        plaintext: bytes = edes_decrypt(ciphertext, key)

    plaintext = remove_pkcs7_padding(plaintext)

    # Output
    print(plaintext.decode("utf-8"), end="")
