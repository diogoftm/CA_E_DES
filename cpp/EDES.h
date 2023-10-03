#pragma once

#include <cstdint>
#include <algorithm>

class EDES
{
public:
    uint8_t *encrypt(uint8_t *in, uint32_t inSize);

private:
    uint8_t *f(uint8_t *in, uint8_t *sbox);
    uint8_t *fN(uint8_t *in, uint8_t *sbox);
    uint8_t *processBlock(uint8_t *in);
};
