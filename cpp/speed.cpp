
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

#define TRIES 5000
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
    OpenSSL_add_all_algorithms();

    Statistics statistics;

    static uint8_t data[TEST_DATA_SIZE];
    static DES_cblock key;
    static uint8_t out[TEST_DATA_SIZE];
    static DES_key_schedule keysched;

    timespec beforeEncT, afterEncT;

    for (unsigned int i = 0; i < TRIES; i++)
    {
        fill_byte_arr_randomly(data, sizeof(data));
        DES_random_key(&key);
        DES_set_key((DES_cblock *)key, &keysched);

        clock_gettime(CLOCK_MONOTONIC, &beforeEncT);


        DES_ecb_encrypt((DES_cblock *)data, (DES_cblock *)out, &keysched, DES_ENCRYPT);

        
        clock_gettime(CLOCK_MONOTONIC, &afterEncT);

        long long elapsed_ns = ELAPSED_NS(beforeEncT, afterEncT);

        if (statistics.lowest_time_ns == UNSET_NS || elapsed_ns < statistics.lowest_time_ns)
            statistics.lowest_time_ns = elapsed_ns;

    }

    return statistics;
}

Statistics test_EDES()
{
    Statistics statistics;

    timespec beforeEncT, afterEncT;

    static uint8_t data[TEST_DATA_SIZE];
    //static uint8_t out[TEST_DATA_SIZE];

    //int out_len;

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

    long long des_slowness = EDES_Stats.lowest_time_ns / DES_Stats.lowest_time_ns;
    fprintf(stdout, "EDES was %lld times slower than DES\n", des_slowness);
}