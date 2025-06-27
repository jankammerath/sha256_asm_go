#include <stdio.h>
#include <string.h>
#include <stdint.h>

void print_hex_bytes(const char* label, const uint8_t* data, size_t len) {
    printf("%s: ", label);
    for (size_t i = 0; i < len; i++) {
        printf("%02x ", data[i]);
    }
    printf("\n");
}

void sha256_debug(const char* input) {
    size_t len = strlen(input);
    printf("Input string: '%s'\n", input);
    printf("Input length: %zu bytes\n", len);
    printf("Input length in bits: %zu\n", len * 8);
    
    // Print input bytes
    print_hex_bytes("Input bytes", (const uint8_t*)input, len);
    
    // Calculate padded length
    size_t padded_len = len + 1 + 8; // +1 for 0x80, +8 for length
    padded_len = ((padded_len + 63) / 64) * 64; // Round up to 64-byte boundary
    
    printf("Padded length: %zu bytes\n", padded_len);
    
    // Create padded message
    uint8_t* padded = calloc(padded_len, 1);
    memcpy(padded, input, len);
    padded[len] = 0x80;
    
    // Store length in bits as big-endian 64-bit
    uint64_t bit_len = len * 8;
    // Store in big-endian format
    for (int i = 0; i < 8; i++) {
        padded[padded_len - 8 + i] = (bit_len >> (56 - i * 8)) & 0xFF;
    }
    
    print_hex_bytes("Padded message", padded, padded_len);
    
    // Print first 16 32-bit words in big-endian format
    printf("First 16 words (big-endian):\n");
    for (int i = 0; i < 16 && i * 4 < padded_len; i++) {
        uint32_t word = (padded[i*4] << 24) | (padded[i*4+1] << 16) | 
                       (padded[i*4+2] << 8) | padded[i*4+3];
        printf("W[%02d] = 0x%08x\n", i, word);
    }
    
    free(padded);
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        printf("Usage: %s <string>\n", argv[0]);
        return 1;
    }
    
    sha256_debug(argv[1]);
    return 0;
}
