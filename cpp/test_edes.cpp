#include "EDES.h"
#include <gtest/gtest.h>

#define FILL(ARR, N, VALUE)              \
    for (unsigned int i = 0; i < N; i++) \
    {                                    \
        ARR[i] = VALUE;                  \
    }

uint8_t rkey[32] = {0x2b, 0x8f, 0x1b, 0x4c, 0x71, 0x51, 0xa3, 0x9d, 0x88, 0xf2, 0x7b, 0x5a, 0x16, 0xc5, 0xe9, 0x3d,
                    0x01, 0x51, 0x93, 0x6f, 0x33, 0xda, 0x77, 0xb5, 0x68, 0x11, 0xf7, 0xa8, 0xd6, 0x45, 0x22, 0x04};

class EDESTest : public ::testing::Test
{
public:
    EDES edes;
    uint8_t key[32] = {0x2b, 0x8f, 0x1b, 0x4c, 0x71, 0x51, 0xa3, 0x9d, 0x88, 0xf2, 0x7b, 0x5a, 0x16, 0xc5, 0xe9, 0x3d,
                       0x01, 0x51, 0x93, 0x6f, 0x33, 0xda, 0x77, 0xb5, 0x68, 0x11, 0xf7, 0xa8, 0xd6, 0x45, 0x22, 0x04};

    void SetUp() override
    {

        edes.set_key(key);
    }

    void TearDown() override
    {
    }
};

TEST(SboxGenerator, SboxValuesDistribution)
{

    SBOXES sboxes;

    SBOXESGenerator::generate(rkey, sboxes);

    unsigned int counting[256];
    FILL(counting, 256, 0);

    for (unsigned int cbox = 0; cbox < 16; cbox++)
    {
        for (unsigned int cpos = 0; cpos < 256; cpos++)
        {
            counting[sboxes[cbox][cpos]] += 1;
        }
    }

    for (unsigned int counting_pos = 0; counting_pos < 256; counting_pos++)
    {
        ASSERT_EQ(counting[counting_pos], 16);
    }
}

TEST_F(EDESTest, EncryptionAndDecryption)
{
    uint8_t input[64] = {0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                         0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                         0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
                         0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
                         0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
                         0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00,
                         0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00,
                         0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01};

    uint8_t *encrypted = edes.encrypt(input, sizeof(input));

    uint8_t *decrypted = edes.decrypt(encrypted, sizeof(input));

    for (unsigned int i = 0; i < sizeof(input); i++)
    {
        EXPECT_EQ(decrypted[i], input[i]);
    }

    // Cleanup
    delete[] encrypted;
    delete[] decrypted;
}

double getKeyBitFlipSboxPercentage(uint8_t *k1, uint8_t *k2)
{
    SBOXES orig, modified;

    SBOXESGenerator::generate(k1, orig);
    SBOXESGenerator::generate(k2, orig);

    int bitsFlipped = 0;

    for (unsigned int i = 0; i < 4096; i++)
    {
        uint8_t b1, b2;
        b1 = orig[i / 256][i % 256];
        b2 = modified[i / 256][i % 256];

        for (int j = 0; j < 8; j++)
        {
            uint8_t bit1 = (b1 >> j) & 0x01;
            uint8_t bit2 = (b2 >> j) & 0x01;

            if (bit1 != bit2)
                bitsFlipped++;
        }
    }

    return 100.0 * (double)bitsFlipped / (4096 * 8.0);
}

void flip_key_1_bit_randomly(uint8_t *key, int keysize)
{
    int rpos = rand() % keysize;
    int ipos = rand() % 8;

    key[rpos] ^= (0x1 << ipos);
}

/*
    Make sure bit flips in the key don't produce
*/
TEST(SboxGenerator, SBOXEntropy)
{
    uint8_t modifiedKey[32];
    memcpy(modifiedKey, rkey, sizeof(rkey));

    uint8_t k1[32];
    uint8_t k2[32];

    memcpy(k1, rkey, sizeof(rkey));
    memcpy(k2, rkey, sizeof(rkey));

    double totalPercentage = 0.0;

    for (unsigned int i = 0; i < 2500; i++)
    {
        flip_key_1_bit_randomly(k2, 32);
        double cpercentage = getKeyBitFlipSboxPercentage(k1, k2);
        totalPercentage += cpercentage;
        // total SBOXES contains 32768 bits, so a difference greater than 1.5% is a bad sign
        ASSERT_NEAR(cpercentage, 50, 1.5);
        memcpy(k1, k2, 32);
    }

    double avg_percentage = totalPercentage / 2500.0;
    ASSERT_NEAR(avg_percentage, 50, 0.5);
}

int main(int argc, char **argv)
{
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}