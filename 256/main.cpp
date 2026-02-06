#include <iostream>
#include <string>
#include <vector>
#include <sstream>
#include <iomanip>
#include <cstdint>

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

    out.push_back(0x80);
    while ((out.size() % 4) != 0) out.push_back(0x00);

    for (int i = 0; i < 8; ++i)
        out.push_back((uint8_t)((bit_len >> (8 * i)) & 0xFF));

    return out;
}

// Non-linear functions
inline uint32_t F(uint32_t x, uint32_t y, uint32_t z) { return (x & y) | (~x & z); }
inline uint32_t G(uint32_t x, uint32_t y, uint32_t z) { return (x & y) | (x & z) | (y & z); }
inline uint32_t H(uint32_t x, uint32_t y, uint32_t z) { return x ^ y ^ z; }
inline uint32_t I(uint32_t x, uint32_t y, uint32_t z) { return y ^ (x | ~z); }

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

    for (size_t i = 0; i < msg.size(); i += 4) {
        uint32_t block = le_bytes_to_u32(msg, i);

        for (int r = 0; r < 24; ++r) {
            uint32_t t0 = rotl32(S[0] + F(S[1], S[2], S[3]) + block + RCON[r], (r % 11) + 1);
            uint32_t t1 = rotl32(S[1] + G(S[2], S[3], S[4]) + block + RCON[(r+3)%24], (r % 13) + 1);
            uint32_t t2 = rotl32(S[2] + H(S[3], S[4], S[5]) + block + RCON[(r+6)%24], (r % 17) + 1);
            uint32_t t3 = rotl32(S[3] + I(S[4], S[5], S[6]) + block + RCON[(r+9)%24], (r % 19) + 1);

            uint32_t t4 = rotl32(S[4] ^ t0, (r % 7) + 1);
            uint32_t t5 = rotl32(S[5] + t1, (r % 9) + 1);
            uint32_t t6 = rotl32(S[6] ^ t2, (r % 13) + 1);
            uint32_t t7 = rotl32(S[7] + t3, (r % 15) + 1);

            // diffusion
            S[0] = t0 ^ (t5 >> 3);
            S[1] = t1 ^ (t6 << 5);
            S[2] = t2 ^ (t7 >> 7);
            S[3] = t3 ^ (t4 << 11);
            S[4] = t4 ^ (t1 >> 2);
            S[5] = t5 ^ (t2 << 3);
            S[6] = t6 ^ (t3 >> 5);
            S[7] = t7 ^ (t0 << 7);
        }

        // feed-forward
        for (int j = 0; j < 8; ++j)
            S[j] ^= rotl32(block + RCON[j], j + 3);
    }

    // final avalanche
    for (int r = 0; r < 16; ++r) {
        for (int j = 0; j < 8; ++j) {
            S[j] += rotl32(S[(j+1)%8] ^ S[(j+3)%8], (r+j)%17 + 1);
            S[j] ^= RCON[(r+j)%24];
        }
    }

    return to_hex256(S);
}

int main() {
    std::string input;
    std::cout << "CipherA-256\n";
    std::cout << "Enter String: ";
    std::getline(std::cin, input);

    std::string hash = CipherA_256(input);
    std::cout << "CipherA-256 Hash: " << hash << "\n";
    return 0;
}
