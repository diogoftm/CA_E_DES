#include "EDES.h"

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <string.h>
#include <iostream>
using namespace std;

void deriveKey(const string& pass, unsigned char* salt, unsigned char* key, unsigned char* iv )
{
  EVP_BytesToKey(EVP_aes_256_cbc(), EVP_sha1(), salt, (unsigned char*)pass.c_str(), pass.length(), 1, key, iv);
}

uint8_t* encrypt(uint8_t* key, uint8_t* plaintext, uint32_t length){
    // Init EDES
    EDES edes = EDES();

    // Encrypt
    // todo: init with key
    uint8_t* ciphertext = edes.encrypt(plaintext, length);

    return ciphertext;
}

uint8_t* padPKCS7(uint8_t* in, size_t dataSize, size_t blockSize) {
    // Calculate the number of padding bytes needed
    size_t paddingSize = blockSize - (dataSize % blockSize);
    
    // Create a new buffer for the padded data
    size_t paddedSize = dataSize + paddingSize;
    uint8_t* paddedData = new uint8_t[paddedSize];

    // Copy the original data into the new buffer
    for (size_t i = 0; i < dataSize; i++) {
        paddedData[i] = in[i];
    }

    // Add padding bytes with the value equal to the number of padding bytes
    for (size_t i = dataSize; i < paddedSize; i++) {
        paddedData[i] = static_cast<uint8_t>(paddingSize);
    }

    return paddedData;
}

int main (int argc, char const *argv[])
{
    if(argc < 3){
        std::cerr << "Invalid number of arguments.\n";
        return -1;
    }

    char* plaintext = (char*) argv[2]; // plaintext from user
    size_t plainLen = strlen(plaintext);

    unsigned char salt[8];
    ERR_load_crypto_strings();

    // Derive key from password
    unsigned char key[32];
    unsigned char iv[32]; // not used
    if (strncmp((const char*)plaintext,"Salted__",8) == 0) {
        memcpy(salt,&plaintext[8],8);
        plaintext += 16;
        plainLen -= 16;
    }
    std::string psw(argv[1]); // password from user
    deriveKey(psw, salt, key, iv);

    uint8_t* paddedData = padPKCS7(reinterpret_cast<uint8_t*>(plaintext), plainLen, 8);
    uint8_t* ciphertext = encrypt(key, paddedData, plainLen + (8 - plainLen % 8));

    for (size_t i = 0; i<(plainLen + (8 - plainLen % 8)); i++) std::cout << ciphertext[i];

    // Clean up
    EVP_cleanup();
    ERR_free_strings();

    return 0;
}
