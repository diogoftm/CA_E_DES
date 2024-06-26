#pragma once

#include <cstdint>
#include <algorithm>
#include <cassert>

typedef uint8_t SBOX[256];

typedef SBOX SBOXES[16];


class SBOXESGenerator {
    public:
        static void generate(uint8_t key[32], SBOXES& sboxes);
    private:
        static void generate_derived_key(uint8_t key[32], uint8_t derived[8192]);
};

class EDES
{
public:
    EDES();

    uint8_t *encrypt(uint8_t *in, uint32_t inSize);
    uint8_t *decrypt(uint8_t *in, uint32_t inSize);
    void set_key(const uint8_t key[32]);


private:
    void processBlockBatch(const uint8_t *in, uint8_t reverseFlag, uint32_t numBlocks, uint8_t *out);
    void setupSboxes();

    uint8_t key[32];
    SBOXES sboxes;
};
