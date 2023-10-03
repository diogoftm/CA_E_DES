
#include <time.h>
#include <functional>
#include <stdio.h>
#include <openssl/des.h>
#include <fcntl.h>
#include <unistd.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

#include "EDES.h"

#define TRIES 5
#define TEST_DATA_SIZE 4096
#define UNSET_NS -1

#define ELAPSED_NS(TA, TB) (TB.tv_sec - TA.tv_sec) * 1000000000LL + (TB.tv_nsec - TA.tv_nsec)

struct Statistics
{
    long long lowest_time_ns = UNSET_NS;
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
    static uint8_t key[DES_KEY_SZ];
    static uint8_t out[TEST_DATA_SIZE];
    int out_len;

    timespec beforeEncT, afterEncT;

    OPENSSL_add_all_algorithms_conf();

    for (unsigned int i = 0; i < TEST_DATA_SIZE; i++)
    {
        fill_byte_arr_randomly(data, sizeof(data));

        EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();

        EVP_EncryptInit_ex(ctx, EVP_des_cfb(), NULL, key, NULL);

        clock_gettime(CLOCK_MONOTONIC, &beforeEncT);

        EVP_EncryptUpdate(ctx, out, &out_len, data, sizeof(data));
        EVP_EncryptFinal_ex(ctx, out + out_len, &out_len);

        clock_gettime(CLOCK_MONOTONIC, &afterEncT);
        long long elapsed_ns = ELAPSED_NS(beforeEncT, afterEncT);

        if (statistics.lowest_time_ns == UNSET_NS || elapsed_ns < statistics.lowest_time_ns)
            statistics.lowest_time_ns = elapsed_ns;

        EVP_CIPHER_CTX_free(ctx);
    }

    return statistics;
}

Statistics test_EDES()
{
    Statistics statistics;

    timespec beforeEncT, afterEncT;

    static uint8_t data[TEST_DATA_SIZE];

    static uint8_t out[TEST_DATA_SIZE];
    int out_len;

    for (unsigned int i = 0; i < TRIES; i++)
    {

        fill_byte_arr_randomly(data, sizeof(data));

        EDES edes = EDES();
        clock_gettime(CLOCK_MONOTONIC, &beforeEncT);

        edes.encrypt(data, sizeof(data));

        clock_gettime(CLOCK_MONOTONIC, &afterEncT);

        long long elapsed_ns = ELAPSED_NS(beforeEncT, afterEncT);

        if (statistics.lowest_time_ns == UNSET_NS || elapsed_ns < statistics.lowest_time_ns)
            statistics.lowest_time_ns = elapsed_ns;
    }

    return statistics;
}

int main(int argc, char *argv[])
{
    Statistics DES_Stats = test_DES();

    Statistics EDES_Stats = test_EDES();

    fprintf(stdout, " DES fastest encryption time: %lldns\n", DES_Stats.lowest_time_ns);
    fprintf(stdout, "EDES fastest encryption time: %lldns\n", EDES_Stats.lowest_time_ns);
}