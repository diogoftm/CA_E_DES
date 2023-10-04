#pragma once

#include <cstdint>
#include <algorithm>
#include <cassert>

class EDES
{
public:
    uint8_t *encrypt(uint8_t *in, uint32_t inSize);
    uint8_t *decrypt(uint8_t *in, uint32_t inSize);
    void set_key(const uint8_t key[32]);

private:
    uint8_t *f(uint8_t *in, uint8_t *sbox);
    uint8_t *fN(uint8_t *in, uint8_t *sbox);
    uint8_t *fNR(uint8_t *in, uint8_t *sbox);
    uint8_t *processBlock(uint8_t *in, uint8_t reverseFlag);
};
