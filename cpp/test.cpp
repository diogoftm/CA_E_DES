#include "EDES.h"
#include <iostream>
#include <cstdint>
#include <cmath>
/*
uint8_t input[64] = {0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                     0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                     0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
                     0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
                     0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
                     0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00,
                     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00,
                     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01};
*/
uint8_t key[32] = {0x2b, 0x8f, 0x1b, 0x4c, 0x71, 0x51, 0xa3, 0x9d, 0x88, 0xf2, 0x7b, 0x5a, 0x16, 0xc5, 0xe9, 0x3d,
                   0x01, 0x51, 0x93, 0x6f, 0x33, 0xda, 0x77, 0xb5, 0x68, 0x11, 0xf7, 0xa8, 0xd6, 0x45, 0x22, 0x04};

int main()
{
    EDES edes = EDES();
    edes.set_key(key);

    uint8_t original_input[8] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    uint8_t modified_input[8];
    
    uint8_t *original_result = edes.encrypt(original_input, 8); // Assuming encrypt() takes an array of 8 uint8_t values

    int total_bit_changes = 0;
    
    for (int i = 0; i < 8; i++) {
        for (int bit = 0; bit < 8; bit++) {
            // Copy the original input to the modified input
            for (int j = 0; j < 8; j++) {
                modified_input[j] = original_input[j];
            }

            // Modify a single bit in the copied input data
            modified_input[i] ^= (1 << bit);

            // Encrypt the modified input data
            uint8_t *modified_result = edes.encrypt(modified_input, 8);

            // Compare and count how many bits changed
            int bit_changes = 0;
            for (int j = 0; j < 8; j++) {
                uint8_t xor_result = original_result[j] ^ modified_result[j];
                bit_changes += __builtin_popcount(xor_result); // Count the number of set bits
            }

            total_bit_changes += bit_changes;

            delete[] modified_result;
        }
    }

    int total_iterations = 8 * 8; // 8 elements with 8 bits each
    double average_bit_changes = static_cast<double>(total_bit_changes) / total_iterations;

    std::cout << "Average number of bit changes: " << average_bit_changes << " (" << round(average_bit_changes) << ")" << std::endl;

    delete[] original_result;

    return 0;
}
