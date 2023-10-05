#include "EDES.h"
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <iostream>
#include <stdexcept>

// TO DO:
// - add assertions

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

void EDES::setupSboxes()
{
    SBOXESGenerator::generate(this->key, this->sboxes);
}
/*
 */
uint8_t *EDES::f(uint8_t *in, uint8_t *sbox)
{
    uint32_t index = in[3];
    uint8_t *out = new uint8_t[4];
    out[0] = sbox[index];
    index = (index + in[2]) % 256;
    out[1] = sbox[index];
    index = (index + in[1]) % 256;
    out[2] = sbox[index];
    index = (index + in[0]) % 256;
    out[3] = sbox[index];
    return out;
}

uint8_t *EDES::fN(uint8_t *in, uint8_t *sbox)
{
    uint8_t l[4] = {in[0], in[1], in[2], in[3]};
    uint8_t r[4] = {in[4], in[5], in[6], in[7]};

    uint8_t *rf = EDES::f(r, sbox);

    uint8_t *result = new uint8_t[8];

    for (int i = 0; i < 4; i++)
    {
        result[i + 4] = l[i] ^ rf[i];
    }
    for (int i = 0; i < 4; i++)
    {
        result[i] = r[i];
    }

    delete[] rf;
    return result;
}

// for decryption
uint8_t *EDES::fNR(uint8_t *in, uint8_t *sbox)
{
    uint8_t l[4] = {in[0], in[1], in[2], in[3]};
    uint8_t r[4] = {in[4], in[5], in[6], in[7]};

    uint8_t *rf = EDES::f(l, sbox);

    uint8_t *result = new uint8_t[8];

    for (int i = 0; i < 4; i++)
    {
        result[i] = r[i] ^ rf[i];
    }
    for (int i = 0; i < 4; i++)
    {
        result[i + 4] = l[i];
    }

    delete[] rf;
    return result;
}

uint8_t *EDES::processBlock(uint8_t *in, uint8_t reverseFlag)
{
    uint8_t *result = in;
    for (int i = 0; i < 16; i++)
    {
        if (reverseFlag == 0)
            result = fN(result, sboxes[i]);
        else
            result = fNR(result, sboxes[15 - i]);
    }
    return result;
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
    for (uint32_t i = 0; i < inSize; i += 8)
    {
        uint8_t block[] = {in[i], in[i + 1], in[i + 2], in[i + 3], in[i + 4], in[i + 5], in[i + 6], in[i + 7]};
        uint8_t *r = processBlock(block, 0);
        std::copy(r, r + 8, result + i);
        delete[] r;
    }
    return result;
}

uint8_t *EDES::decrypt(uint8_t *in, uint32_t inSize)
{
    assert((inSize % 8 == 0));
    uint8_t *result = new uint8_t[inSize];
    for (uint32_t i = 0; i < inSize; i += 8)
    {
        uint8_t block[] = {in[i], in[i + 1], in[i + 2], in[i + 3], in[i + 4], in[i + 5], in[i + 6], in[i + 7]};
        uint8_t *r = processBlock(block, 1);
        std::copy(r, r + 8, result + i);
        delete[] r;
    }
    return result;
}
