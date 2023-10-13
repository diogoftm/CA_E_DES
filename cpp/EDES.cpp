#include "EDES.h"
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <iostream>
#include <stdexcept>
#include <algorithm>
#include <unistd.h>
#include <sys/wait.h>
#include <cstring>

void SBOXESGenerator::generate(uint8_t key[32], SBOXES &sboxes)
{
    uint8_t derivedKey[8192];

    SBOXESGenerator::generate_derived_key(key, derivedKey);

    uint16_t *halfWordsDerivedKey = (uint16_t *)derivedKey;

    uint16_t shuffledArray[4096];

    for (uint16_t i = 0; i < 4096; i++)
        shuffledArray[i] = i;

    for (uint16_t i = 0; i < 4095; i++)
    {
        uint16_t j = halfWordsDerivedKey[i] % 4096;

        uint16_t valueJ = shuffledArray[j];
        uint16_t valueI = shuffledArray[i];

        shuffledArray[j] = valueI;
        shuffledArray[i] = valueJ;
    }

    uint8_t currentValue = 0;
    uint32_t currentIteration = 0;
    for (uint32_t idx = 0; idx < 4096; idx++)
    {
        uint32_t position = shuffledArray[idx];
        sboxes[position / 256][position % 256] = currentValue;

        currentIteration++;
        if (currentIteration >= 16)
        {
            currentIteration = 0;
            currentValue++;
        }
    }
}

void SBOXESGenerator::generate_derived_key(uint8_t key[32], uint8_t derived[8192])
{
    for (uint32_t i = 0; i < 8192; i++)
        derived[i] = 0x00;

    unsigned int num_iterations = 8192 / SHA256_DIGEST_LENGTH;
    unsigned int derived_offset = 0;
    unsigned int mdLen;

    for (unsigned int i = 0; i < num_iterations; i++)
    {
        EVP_MD_CTX *mdCtx = EVP_MD_CTX_new();
        if (mdCtx == nullptr)
        {
            throw std::runtime_error("Memory allocation failure for mdCtx");
        }

        if (EVP_DigestInit_ex(mdCtx, EVP_sha256(), NULL) != 1)
        {
            EVP_MD_CTX_free(mdCtx);
            throw std::runtime_error("EVP_DigestInit_ex failed");
        }

        if (EVP_DigestUpdate(mdCtx, key, 32) != 1)
        {
            EVP_MD_CTX_free(mdCtx);
            throw std::runtime_error("EVP_DigestUpdate failed");
        }

        if (derived_offset != 0 && EVP_DigestUpdate(mdCtx, derived + derived_offset - SHA256_DIGEST_LENGTH, 32) != 1)
        {
            EVP_MD_CTX_free(mdCtx);
            throw std::runtime_error("EVP_DigestUpdate failed");
        }

        if (EVP_DigestFinal_ex(mdCtx, derived + derived_offset, &mdLen) != 1)
        {
            EVP_MD_CTX_free(mdCtx);
            throw std::runtime_error("EVP_DigestFinal_ex failed");
        }

        derived_offset += SHA256_DIGEST_LENGTH;

        EVP_MD_CTX_free(mdCtx);
    }
}

EDES::EDES()
{
    uint8_t default_key[32];

    for (unsigned int i = 0; i < 32; i++)
        default_key[i] = 0;

    set_key(default_key);
}

inline void EDES::setupSboxes()
{
    SBOXESGenerator::generate(this->key, this->sboxes);
}

void EDES::processBlockBatch(const uint8_t *in, uint8_t reverseFlag, uint32_t numBlocks, uint8_t *out)
{
    uint8_t *blockOut;

    uint8_t *result;
    uint8_t *sbox;

    uint8_t *in_copy = new uint8_t[numBlocks * 8];

    std::copy(in, in + numBlocks * 8, in_copy);

    for (uint32_t i = 0; i < numBlocks; i++)
    {
        result = in_copy + i * 8;
        blockOut = out + i * 8;
        for (int i = 0; i < 16; i++)
        {
            if (reverseFlag == 0)
            {
                uint8_t r[4] = {result[4], result[5], result[6], result[7]};
                sbox = sboxes[i];
                result[4] = result[0] ^ sbox[r[3]];
                result[5] = result[1] ^ sbox[(r[3] + r[2]) % 256];
                result[6] = result[2] ^ sbox[(((r[3] + r[2]) % 256) + r[1]) % 256];
                result[7] = result[3] ^ sbox[(((((r[3] + r[2]) % 256) + r[1]) % 256) + r[0]) % 256];
                std::memcpy(result, r, 4);
            }
            else
            {
                uint8_t l[4] = {result[0], result[1], result[2], result[3]};
                sbox = sboxes[15 - i];
                result[0] = result[4] ^ sbox[l[3]];
                result[1] = result[5] ^ sbox[(l[3] + l[2]) % 256];
                result[2] = result[6] ^ sbox[(((l[3] + l[2]) % 256) + l[1]) % 256];
                result[3] = result[7] ^ sbox[(((((l[3] + l[2]) % 256) + l[1]) % 256) + l[0]) % 256];
                std::memcpy(result + 4, l, 4);
            }
        }

        std::memcpy(blockOut, result, 8);
    }

    delete[] in_copy;
}

// public methods

void EDES::set_key(const uint8_t key[32])
{
    std::copy(key, key + 32, this->key);
    setupSboxes();
}

uint8_t *EDES::encrypt(uint8_t *in, uint32_t inSize)
{
    assert((inSize % 8 == 0));
    uint8_t *result = new uint8_t[inSize];

    processBlockBatch(in, 0, inSize / 8, result);
    return result;
}

uint8_t *EDES::decrypt(uint8_t *in, uint32_t inSize)
{
    assert((inSize % 8 == 0));
    uint8_t *result = new uint8_t[inSize];
    processBlockBatch(in, 1, inSize / 8, result);
    return result;
}
