#include "EDES.h"

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <openssl/des.h>
#include <string.h>
#include <iostream>
#include "opensslSetup.h"

using namespace std;

// Base64 encode
std::string base64Encode(const uint8_t *data, size_t length)
{
    BIO *bio = BIO_new(BIO_s_mem());
    BIO *base64 = BIO_new(BIO_f_base64());
    BIO_push(base64, bio);

    // Prevent line breaks in the output
    BIO_set_flags(base64, BIO_FLAGS_BASE64_NO_NL);

    BIO_write(base64, data, length);
    BIO_flush(base64);

    BUF_MEM *bufferPtr;
    BIO_get_mem_ptr(bio, &bufferPtr);

    std::string encodedData(bufferPtr->data, bufferPtr->length);

    BIO_free_all(base64);

    return encodedData;
}

// Derive key from password (iv not used)
void deriveKey(const string &pass, unsigned char *salt, unsigned char *key, unsigned char *iv)
{
    EVP_BytesToKey(EVP_aes_256_ecb(), EVP_sha256(), salt, (unsigned char *)pass.c_str(), pass.length(), 1, key, iv);
}

// Encrypt using E-DES
uint8_t *encrypt(uint8_t *key, uint8_t *plaintext, uint32_t length)
{
    EDES edes = EDES();

    edes.set_key(key);
    uint8_t *ciphertext = edes.encrypt(plaintext, length);

    return ciphertext;
}

// Encrypt using DES
uint8_t *encryptDES(uint8_t *key, uint8_t *ciphertext, uint32_t length)
{
    uint8_t *out = new uint8_t[length];

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int len;
    EVP_EncryptInit(ctx, EVP_des_ecb(), key, NULL);

    for (unsigned int i = 0; i < length; i += 8)
    {
        EVP_EncryptUpdate(ctx, out + i, &len, ciphertext + i, 8);
    }

    EVP_CIPHER_CTX_free(ctx);

    return out;
}

// Add PKCS#7 padding
uint8_t *padPKCS7(uint8_t *in, size_t dataSize, size_t blockSize)
{
    size_t paddingSize = blockSize - (dataSize % blockSize);

    size_t paddedSize = dataSize + paddingSize;
    uint8_t *paddedData = new uint8_t[paddedSize];

    for (size_t i = 0; i < dataSize; i++)
    {
        paddedData[i] = in[i];
    }

    for (size_t i = dataSize; i < paddedSize; i++)
    {
        paddedData[i] = static_cast<uint8_t>(paddingSize);
    }

    return paddedData;
}

int main(int argc, char const *argv[])
{
    opensslSetup();
    char standardDESFlag = 0;

    // Check command line arguments
    if (argc == 2)
    {
        if (strcmp(argv[1], "-h") == 0)
        {
            std::cout << "usage: ./encrypt <password> [-s]\n";
            return 0;
        }
    }
    else
    {
        if (strcmp(argv[2], "-s") == 0)
            standardDESFlag = 1;
        else if (argc == 2)
        {
            std::cerr << "Invalid flag. Use -h for help. \n";
            return -1;
        }
        else
        {
            std::cerr << "Invalid number of arguments. Use -h for help. \n";
            return -1;
        }
    }

    std::string dataIn;
    std::string line;
    while (std::getline(std::cin, line))
    {
        dataIn += line;
    }
    char *plaintext = new char[dataIn.length() + 1]; // +1 for the null terminator
    strcpy(plaintext, dataIn.c_str());
    size_t plainLen = strlen(plaintext);

    // Derive key from password
    unsigned char salt[8] = {0x01, 0x02, 0xFA, 0x00, 0x98, 0x11, 0x1D, 0xDD};
    ERR_load_crypto_strings();
    unsigned char key[32];
    unsigned char iv[32]; // not used

    std::string psw(argv[1]); // password from user
    deriveKey(psw, salt, key, iv);

    // Padding
    uint8_t *paddedData = padPKCS7(reinterpret_cast<uint8_t *>(plaintext), plainLen, 8);

    // Encrypt
    uint8_t *ciphertext;
    if (standardDESFlag)
        ciphertext = encryptDES(key, paddedData, plainLen + (8 - plainLen % 8));
    else
        ciphertext = encrypt(key, paddedData, plainLen + (8 - plainLen % 8));

    // Base 64 encode
    std::string ciphertextBase64 = base64Encode(ciphertext, plainLen + (8 - plainLen % 8));

    // Output
    std::cout << ciphertextBase64 << std::endl;

    // Clean up
    EVP_cleanup();
    ERR_free_strings();

    return 0;
}
