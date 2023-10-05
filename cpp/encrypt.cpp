#include "EDES.h"

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <openssl/des.h>
#include <string.h>
#include <iostream>
using namespace std;

std::string base64Encode(const uint8_t* data, size_t length) {
    BIO* bio = BIO_new(BIO_s_mem());
    BIO* base64 = BIO_new(BIO_f_base64());
    BIO_push(base64, bio);

    // Prevent line breaks in the output
    BIO_set_flags(base64, BIO_FLAGS_BASE64_NO_NL);

    BIO_write(base64, data, length);
    BIO_flush(base64);

    BUF_MEM* bufferPtr;
    BIO_get_mem_ptr(bio, &bufferPtr);

    std::string encodedData(bufferPtr->data, bufferPtr->length);

    BIO_free_all(base64);

    return encodedData;
}

void deriveKey(const string& pass, unsigned char* salt, unsigned char* key, unsigned char* iv )
{
    EVP_BytesToKey(EVP_aes_256_cbc(), EVP_sha1(), salt, (unsigned char*)pass.c_str(), pass.length(), 1, key, iv);
}

// E-DES encrypt
uint8_t* encrypt(uint8_t* key, uint8_t* plaintext, uint32_t length){
    // Init EDES
    EDES edes = EDES();

    // Encrypt
    edes.set_key(key);
    uint8_t* ciphertext = edes.encrypt(plaintext, length);

    return ciphertext;
}

uint8_t* encryptDES(uint8_t* key, uint8_t* ciphertext, uint32_t length) {
    OpenSSL_add_all_algorithms();

    uint8_t* out = new uint8_t[length];
    DES_key_schedule keysched;

    DES_set_key((DES_cblock *)key, &keysched);

    for (int i = 0; i < length; i += 8) {
        DES_ecb_encrypt((DES_cblock *)(ciphertext + i), (DES_cblock *)(out + i), &keysched, DES_ENCRYPT);
    }

    return out;
}


// PKCS#7 padding   
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
    char standardDESFlag = 0;

    // Check command line arguments
    if(argc < 3){
        if(argc == 2 && strcmp(argv[1],"-h") == 0){
            std::cout << "usage: ./encrypt <password> <plaintext> [-s]";
        }
        std::cerr << "Invalid number of arguments. Use -h for help. \n";
        return -1;
    } else if(argc > 3){
        if(strcmp(argv[3],"-s") == 0) standardDESFlag = 1;
        else if (argc == 3){
            std::cerr << "Invalid flag. Use -h for help. \n";
            return -1;
        } else{
            std::cerr << "Invalid number of arguments. Use -h for help. \n";
            return -1;
        }
    }

    char* plaintext = (char*) argv[2]; // plaintext from user
    size_t plainLen = strlen(plaintext);

    unsigned char salt[8] = {0x01, 0x02, 0xFA, 0x00, 0x98, 0x11, 0x1D, 0xDD};
    ERR_load_crypto_strings();

    // Derive key from password
    unsigned char key[32];
    unsigned char iv[32]; // not used
    std::string psw(argv[1]); // password from user
    deriveKey(psw, salt, key, iv);

    // Padding
    uint8_t* paddedData = padPKCS7(reinterpret_cast<uint8_t*>(plaintext), plainLen, 8);

    // Encrypt
    uint8_t* ciphertext;
    if(standardDESFlag) ciphertext = encryptDES(key, paddedData, plainLen + (8 - plainLen % 8));
    else ciphertext = encrypt(key, paddedData, plainLen + (8 - plainLen % 8));

    // Base 64 encode
    std::string ciphertextBase64 = base64Encode(ciphertext, plainLen + (8 - plainLen % 8));

    // Output
    std::cout << ciphertextBase64 << std::endl;

    // Clean up
    EVP_cleanup();
    ERR_free_strings();

    return 0;
}