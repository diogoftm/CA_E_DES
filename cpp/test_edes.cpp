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

    for (int i = 0; i < sizeof(input); i++)
    {
        EXPECT_EQ(decrypted[i], input[i]);
    }

    // Cleanup
    delete[] encrypted;
    delete[] decrypted;
}

int main(int argc, char **argv)
{
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}