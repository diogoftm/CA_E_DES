#include "EDES.h"
#include <iostream>
#include <cstdint>
#include <cmath>

uint8_t key[32] = {0x2b, 0x8f, 0x1b, 0x4c, 0x71, 0x51, 0xa3, 0x9d, 0x88, 0xf2, 0x7b, 0x5a, 0x16, 0xc5, 0xe9, 0x3d,
                   0x01, 0x51, 0x93, 0x6f, 0x33, 0xda, 0x77, 0xb5, 0x68, 0x11, 0xf7, 0xa8, 0xd6, 0x45, 0x22, 0x04};


double getNumberOfDiffusionBits(){
    EDES edes = EDES();
    edes.set_key(key);

    uint8_t original_input[8] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    uint8_t modified_input[8];
    
    uint8_t *original_result = edes.encrypt(original_input, 8);

    int total_bit_changes = 0;
    
    for (int i = 0; i < 8; i++) {
        for (int bit = 0; bit < 8; bit++) {
            for (int j = 0; j < 8; j++) {
                modified_input[j] = original_input[j];
            }

            modified_input[i] ^= (1 << bit);

            uint8_t *modified_result = edes.encrypt(modified_input, 8);

            int bit_changes = 0;
            for (int j = 0; j < 8; j++) {
                uint8_t xor_result = original_result[j] ^ modified_result[j];
                bit_changes += __builtin_popcount(xor_result);
            }

            total_bit_changes += bit_changes;

            delete[] modified_result;
        }
    }

    int total_iterations = 8 * 8;
    double average_bit_changes = static_cast<double>(total_bit_changes) / total_iterations;
    return average_bit_changes;
}

double getNumberOfConfusionBits(){
    EDES edes = EDES();
    edes.set_key(key);
    uint8_t input[8] = {0x0A, 0x0B, 0xA0, 0xB0, 0x11, 0x00, 0x2F, 0x10};
    uint8_t modified_key[32];
    
    uint8_t *result = edes.encrypt(input, 8);

    int total_bit_changes = 0;
    
    for (int i = 0; i < 32; i++) {
        for (int bit = 0; bit < 8; bit++) {
            for (int j = 0; j < 32; j++) {
                modified_key[j] = key[j];
            }

            modified_key[i] ^= (1 << bit);
            edes.set_key(modified_key);

            uint8_t *modified_result = edes.encrypt(input, 8);

            int bit_changes = 0;
            for (int j = 0; j < 8; j++) {
                uint8_t xor_result = result[j] ^ modified_result[j];
                bit_changes += __builtin_popcount(xor_result);
            }

            total_bit_changes += bit_changes;

            delete[] modified_result;
        }
    }

    int total_iterations = 8 * 32;
    double average_bit_changes = static_cast<double>(total_bit_changes) / total_iterations;
    return average_bit_changes;
}

int main()
{
    double diff_bit_changes = getNumberOfDiffusionBits();
    std::cout << "Diffusion bits: " << diff_bit_changes << " (" << round(diff_bit_changes) << ")" << std::endl;

    double conf_bit_changes = getNumberOfConfusionBits();
    std::cout << "Confusion bits: " << conf_bit_changes << " (" << round(conf_bit_changes) << ")" << std::endl;

    return 0;
}
