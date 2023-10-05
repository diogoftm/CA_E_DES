from Crypto.Cipher import DES
from Crypto.Protocol.KDF import PBKDF2
import base64
import hashlib
import sys

# Base64 encode
def base64Encode(data : bytes) -> bytes:
    return base64.b64encode(data).decode('utf-8')

# Derive key and iv from password, matching cpp EVP_BytesToKey
def deriveKey(passphrase : str, salt : bytes) -> bytes:
    iterations : int = 1  # Equivalent to the "1" argument in EVP_BytesToKey
    key_len : int = 8  # DES key length

    # Concatenate the password and salt
    data : bytes = passphrase.encode() + salt

    # Perform SHA-1 hashing for the given number of iterations
    for _ in range(iterations):
        data = hashlib.sha1(data).digest()

    # Take the first 8 bytes as the key
    key : bytes = data[:key_len]

    return key

# Encrypt using pycryptodome DES
def des_encrypt(plaintext : bytes, key : bytes) -> bytes:
    cipher = DES.new(key, DES.MODE_ECB)
    ciphertext : bytes = cipher.encrypt(plaintext)
    return ciphertext

# Encrypt using E-DES
def edes_encrypt(plaintext : bytes, key : bytes) -> bytes:
    ...

# Add PKCS#7 pad
def pkcs7_pad(data : bytes, block_size : int) -> bytes:
    padding : int = block_size - (len(data) % block_size)
    return data + bytes([padding] * padding)

if __name__ == "__main__":
    standardDESFlag : bool = False

    # Check command line arguments
    if len(sys.argv) < 3:
        if len(sys.argv) == 2 and sys.argv[1]=="-h":
            print("usage: python3 encrypt.py <password> <plaintext> [-s]")
            sys.exit(0)
    elif len(sys.argv) > 3:
        if sys.argv[3] == "-s":
            standardDESFlag = True
        elif len(sys.argv) == 3:
            print("Invalid flag. Use -h for help.")
            sys.exit(1)
        else:
            print("Invalid number of arguments. Use -h for help.")
            sys.exit(1)
        

    password : str = sys.argv[1]
    plaintext : str = sys.argv[2]

    salt : bytes = bytes([0x01, 0x02, 0xFA, 0x00, 0x98, 0x11, 0x1D, 0xDD])
    # Derive key from password
    key = deriveKey(password, salt)

    # Encrypt
    if standardDESFlag:
        ciphertext : bytes = des_encrypt(pkcs7_pad(plaintext.encode(), DES.block_size), key)
    else:
        print("Not yet implemented")
        sys.exit(1)
    # Base 64 encode
    ciphertext_base64 : bytes = base64Encode(ciphertext)

    # Output
    print(ciphertext_base64)