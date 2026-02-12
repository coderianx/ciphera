#include <iostream>
#include <string>
#include <vector>
#include <sstream>
#include <iomanip>
#include <cstdint>
#include <algorithm>

inline uint32_t rotl32(uint32_t x, unsigned int r) {
    return (x << r) | (x >> (32 - r));
}

uint32_t le_bytes_to_u32(const std::vector<uint8_t>& buf, size_t idx) {
    return (uint32_t)buf[idx]
         | ((uint32_t)buf[idx + 1] << 8)
         | ((uint32_t)buf[idx + 2] << 16)
         | ((uint32_t)buf[idx + 3] << 24);
}

std::vector<uint8_t> pad_message(const std::string& input) {
    std::vector<uint8_t> out(input.begin(), input.end());
    uint64_t bit_len = (uint64_t)input.size() * 8ULL;

    // append 1 bit
    out.push_back(0x80);

    // pad until 56 mod 64
    while ((out.size() % 64) != 56)
        out.push_back(0x00);

    // append length (little endian)
    for (int i = 0; i < 8; ++i)
        out.push_back((uint8_t)((bit_len >> (8 * i)) & 0xFF));

    return out;
}

// Non-linear functions
inline uint32_t F(uint32_t x, uint32_t y, uint32_t z) { return (x & y) | (~x & z); }
inline uint32_t G(uint32_t x, uint32_t y, uint32_t z) { return (x & y) | (x & z) | (y & z); }
inline uint32_t H(uint32_t x, uint32_t y, uint32_t z) { return x ^ y ^ z; }

std::string to_hex256(const uint32_t s[8]) {
    std::stringstream ss;
    ss << std::hex << std::setfill('0');
    for (int i = 0; i < 8; ++i)
        ss << std::setw(8) << s[i];
    return ss.str();
}

std::string CipherA_256(const std::string& input) {

    uint32_t S[8] = {
        0x243F6A88u, 0x85A308D3u, 0x13198A2Eu, 0x03707344u,
        0xA4093822u, 0x299F31D0u, 0x082EFA98u, 0xEC4E6C89u
    };

    const uint32_t RCON[24] = {
        0x9E3779B9u, 0x7F4A7C15u, 0xC6EF3720u, 0x165667B1u,
        0x85EBCA6Bu, 0x27D4EB2Fu, 0xB7E15163u, 0x9DDFEA76u,
        0xE08C1D64u, 0x4F1BBCDCu, 0xA3B19535u, 0x6C62272Eu,
        0xFBF44E5Fu, 0x1C6EF372u, 0xE12B4F97u, 0xC6D3A7E4u,
        0xD1B54A32u, 0xA54FF53Au, 0x510E527Fu, 0x9B05688Cu,
        0x1F83D9ABu, 0x5BE0CD19u, 0xC1059ED8u, 0x367CD507u
    };

    std::vector<uint8_t> msg = pad_message(input);

    // Process 64-byte blocks
    for (size_t i = 0; i < msg.size(); i += 64) {

        uint32_t M[16];
        for (int j = 0; j < 16; ++j)
            M[j] = le_bytes_to_u32(msg, i + j * 4);

        // 32 compression rounds
        for (int r = 0; r < 32; ++r) {

            for (int j = 0; j < 8; ++j) {

                uint32_t mix =
                    F(S[(j+1)%8], S[(j+2)%8], S[(j+3)%8]) +
                    G(S[(j+2)%8], S[(j+3)%8], S[(j+4)%8]) +
                    H(S[(j+3)%8], S[(j+4)%8], S[(j+5)%8]);

                uint32_t data = M[(r + j) % 16];

                uint32_t temp = rotl32(
                    S[j] + mix + data + RCON[(r + j) % 24],
                    ((r * j) % 23) + 3
                );

                S[j] = temp ^ rotl32(S[(j+5)%8], (j+r)%17 + 1);
            }

            // state shuffle
            std::swap(S[0], S[3]);
            std::swap(S[1], S[6]);
            std::swap(S[2], S[5]);
        }

        // Feed-forward (block dependent)
        for (int j = 0; j < 8; ++j)
            S[j] += M[j];
    }

    // Final avalanche phase
    for (int r = 0; r < 24; ++r) {
        for (int j = 0; j < 8; ++j) {
            S[j] ^= rotl32(S[(j+2)%8] + S[(j+5)%8], (r+j)%19 + 3);
            S[j] += RCON[(r+j)%24];
        }
    }

    return to_hex256(S);
}

int main() {
    std::string input;

    std::cout << "CipherA-256 v2\n";
    std::cout << "Enter String: ";
    std::getline(std::cin, input);

    std::string hash = CipherA_256(input);

    std::cout << "CipherA-256 Hash:\n" << hash << "\n";

    return 0;
}
