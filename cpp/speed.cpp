
#include <time.h>
#include <functional>
#include <stdio.h>
#include <openssl/des.h>
#include <fcntl.h>
#include <unistd.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include "EDES.h"
#include <openssl/rand.h>
#include <openssl/conf.h>
#include "opensslSetup.h"

#define TRIES 5000
#define TEST_DATA_SIZE 4096
#define UNSET_NS -1

#define ELAPSED_NS(TA, TB) (TB.tv_sec - TA.tv_sec) * 1000000000LL + (TB.tv_nsec - TA.tv_nsec)

struct Statistics
{
    long long lowest_time_ns = UNSET_NS;
    long long highest_time_ns = UNSET_NS;
    long long average_time_ns = 0;
};

void fill_byte_arr_randomly(uint8_t arr[], unsigned int arr_length)
{
    int fd = open("/dev/urandom", O_RDONLY);
    read(fd, arr, arr_length);
    close(fd);
}

Statistics test_DES()
{
    Statistics statistics;

    static uint8_t data[TEST_DATA_SIZE];
    static DES_cblock key;
    static uint8_t out[TEST_DATA_SIZE];
    static DES_key_schedule keysched;

    statistics.average_time_ns = 0;

    timespec beforeEncT, afterEncT;

    for (unsigned int i = 0; i < TRIES; i++)
    {
        fill_byte_arr_randomly(data, sizeof(data));

        auto ctx = EVP_CIPHER_CTX_new();

        EVP_EncryptInit(ctx, EVP_des_ecb(), key, NULL);

        clock_gettime(CLOCK_MONOTONIC, &beforeEncT);

        int len;
        for (unsigned int i = 0; i < TEST_DATA_SIZE; i += 8)
        {
            EVP_EncryptUpdate(ctx, out + i, &len, data + i, 8);
        }

        clock_gettime(CLOCK_MONOTONIC, &afterEncT);

        EVP_CIPHER_CTX_free(ctx);

        long long elapsed_ns = ELAPSED_NS(beforeEncT, afterEncT);

        if (statistics.lowest_time_ns == UNSET_NS || elapsed_ns < statistics.lowest_time_ns)
            statistics.lowest_time_ns = elapsed_ns;

        if(statistics.highest_time_ns == UNSET_NS || elapsed_ns > statistics.highest_time_ns)
            statistics.highest_time_ns = elapsed_ns;

        statistics.average_time_ns += elapsed_ns;
    }

    statistics.average_time_ns /= TRIES;

    return statistics;
}

Statistics test_EDES()
{
    Statistics statistics;

    timespec beforeEncT, afterEncT;

    static uint8_t data[TEST_DATA_SIZE];
    // static uint8_t out[TEST_DATA_SIZE];

    // int out_len;

    for (unsigned int i = 0; i < TRIES; i++)
    {

        fill_byte_arr_randomly(data, sizeof(data));

        EDES edes = EDES();
        uint8_t key[32] = {0x2b, 0x8f, 0x1b, 0x4c, 0x71, 0x51, 0xa3, 0x9d, 0x88, 0xf2, 0x7b, 0x5a, 0x16, 0xc5, 0xe9, 0x3d,
                   0x01, 0x51, 0x93, 0x6f, 0x33, 0xda, 0x77, 0xb5, 0x68, 0x11, 0xf7, 0xa8, 0xd6, 0x45, 0x22, 0x04};
        edes.set_key(key);
        clock_gettime(CLOCK_MONOTONIC, &beforeEncT);

        edes.encrypt(data, sizeof(data));

        clock_gettime(CLOCK_MONOTONIC, &afterEncT);

        long long elapsed_ns = ELAPSED_NS(beforeEncT, afterEncT);

        if (statistics.lowest_time_ns == UNSET_NS || elapsed_ns < statistics.lowest_time_ns)
            statistics.lowest_time_ns = elapsed_ns;

        if(statistics.highest_time_ns == UNSET_NS || elapsed_ns > statistics.highest_time_ns)
            statistics.highest_time_ns = elapsed_ns;

        statistics.average_time_ns += elapsed_ns;
    }

    statistics.average_time_ns /= TRIES;

    return statistics;
}

void printStatisticsComparison(const Statistics& stats1, const Statistics& stats2) {




    printf("Statistics Comparison between DES and EDES [%d test cases]:\n", TRIES);
    printf("DES - Lowest Time: %lld ns\n", stats1.lowest_time_ns);
    printf("EDES - Lowest Time: %lld ns\n", stats2.lowest_time_ns);

    printf("\n");

    printf("DES - Highest Time: %lld ns\n", stats1.highest_time_ns);
    printf("EDES - Highest Time: %lld ns\n", stats2.highest_time_ns);

    printf("\n");

    printf("DES - Average Time: %lld ns\n", stats1.average_time_ns);
    printf("EDES - Average Time: %lld ns\n", stats2.average_time_ns);
}

int main(int argc, char *argv[])
{

    opensslSetup();

    Statistics DES_Stats = test_DES();
    Statistics EDES_Stats = test_EDES();

    printStatisticsComparison(DES_Stats, EDES_Stats);
    

}
