#include "EDES.h"

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <openssl/des.h>

#include <string.h>
#include "opensslSetup.h"
#include <iostream>
using namespace std;

// Calculates the length of a decoded string
size_t calcDecodeLength(const char *b64input)
{
    size_t len = strlen(b64input),
           padding = 0;

    return (len * 3) / 4 - padding;
}

// Base64 decode
int Base64Decode(char *b64message, unsigned char **buffer, size_t *length)
{
    BIO *bio, *b64;

    int decodeLen = calcDecodeLength(b64message);
    *buffer = (unsigned char *)malloc(decodeLen + 1);
    (*buffer)[decodeLen] = '\0';

    bio = BIO_new_mem_buf(b64message, -1);
    b64 = BIO_new(BIO_f_base64());
    bio = BIO_push(b64, bio);

    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL); // Do not use newlines to flush buffer
    *length = BIO_read(bio, *buffer, strlen(b64message));

    BIO_free_all(bio);

    return (0); // success
}

// Derive key and iv from password (iv not used)
void deriveKey(const string &pass, unsigned char *salt, unsigned char *key, unsigned char *iv)
{
    EVP_BytesToKey(EVP_aes_256_ecb(), EVP_sha256(), salt, (unsigned char *)pass.c_str(), pass.length(), 1, key, iv);
}

// Remove PKCS#7 padding
std::pair<uint8_t *, unsigned int> removePKCS7Padding(const uint8_t *data, size_t dataSize)
{
    if (dataSize == 0)
    {
        return std::make_pair<uint8_t *, unsigned int>(nullptr, 0);
    }

    uint8_t paddingValue = data[dataSize - 1];

    if (paddingValue <= dataSize)
    {
        bool validPadding = true;
        for (size_t i = dataSize - paddingValue; i < dataSize; i++)
        {
            if (data[i] != paddingValue)
            {
                validPadding = false;
                break;
            }
        }

        if (validPadding)
        {
            size_t unpaddedSize = dataSize - paddingValue;
            uint8_t *unpaddedData = new uint8_t[unpaddedSize];
            memcpy(unpaddedData, data, unpaddedSize);
            return std::make_pair<uint8_t *, unsigned int>((uint8_t *)unpaddedData, (unsigned int)unpaddedSize);
        }
    }

    return std::make_pair<uint8_t *, unsigned int>(nullptr, 0);
}

// Decrypt using E-DES
uint8_t *decrypt(uint8_t *key, uint8_t *ciphertext, uint32_t length)
{
    EDES edes = EDES();

    edes.set_key(key);
    uint8_t *plaintext = edes.decrypt(ciphertext, length);

    return plaintext;
}

// Decrypt using DES
uint8_t *decryptDES(uint8_t *key, uint8_t *ciphertext, uint32_t length)
{
    // Sticking with the low-level DES API due to prior issues with EVP decryption

    uint8_t *out = new uint8_t[length];
    DES_key_schedule keysched;

    DES_set_key((DES_cblock *)key, &keysched);

    for (unsigned int i = 0; i < length; i += 8)
    {
        DES_ecb_encrypt((DES_cblock *)(ciphertext + i), (DES_cblock *)(out + i), &keysched, DES_DECRYPT);
    }

    return out;
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
    std::getline(std::cin, dataIn);
    char *ciphertextBase64 = new char[dataIn.length() + 1]; // +1 for the null terminator
    strcpy(ciphertextBase64, dataIn.c_str());

    // Derive key from password
    unsigned char salt[8] = {0x01, 0x02, 0xFA, 0x00, 0x98, 0x11, 0x1D, 0xDD};
    ERR_load_crypto_strings();
    unsigned char key[32];
    unsigned char iv[32];     // not used
    std::string psw(argv[1]); // password from user
    deriveKey(psw, salt, key, iv);

    // Decode Base64-encoded ciphertext
    size_t decodedSize;
    unsigned char *ciphertext;
    Base64Decode(ciphertextBase64, &ciphertext, &decodedSize);

    // Decrypt the ciphertext
    uint8_t *decryptedData;
    if (standardDESFlag)
        decryptedData = decryptDES(key, ciphertext, decodedSize);
    else
        decryptedData = decrypt(key, ciphertext, decodedSize);

    // Remove PKCS#7 padding from the decrypted data
    std::pair<uint8_t *, unsigned int> unpadded = removePKCS7Padding(decryptedData, decodedSize);

    for (unsigned int i = 0; i < unpadded.second; i++)
        std::cout << unpadded.first[i];

    std::cout << std::endl;

    // Clean up
    delete[] ciphertext;
    delete[] decryptedData;
    if (unpadded.first)
        delete[] unpadded.first;
    EVP_cleanup();
    ERR_free_strings();

    return 0;
}
