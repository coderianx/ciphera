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

    for (int i = 0; i < 8; ++i) {
        out.push_back((uint8_t)((bit_len >> (8 * i)) & 0xFF));
    }
    return out;
}

std::string to_hex(uint32_t a, uint32_t b, uint32_t c, uint32_t d) {
    std::stringstream ss;
    ss << std::hex << std::setfill('0')
       << std::setw(8) << a
       << std::setw(8) << b
       << std::setw(8) << c
       << std::setw(8) << d;
    return ss.str();
}

// -----------------------------
// Non-linear functions
// -----------------------------
inline uint32_t F(uint32_t x, uint32_t y, uint32_t z) { return (x & y) | (~x & z); }
inline uint32_t G(uint32_t x, uint32_t y, uint32_t z) { return (x & y) | (x & z) | (y & z); }
inline uint32_t H(uint32_t x, uint32_t y, uint32_t z) { return x ^ y ^ z; }

std::string CipherA_128(const std::string &input) {
    uint32_t A = 0x243F6A88u;
    uint32_t B = 0x85A308D3u;
    uint32_t C = 0x13198A2Eu;
    uint32_t D = 0x03707344u;
  
    const uint32_t RCON[16] = {
        0x9E3779B9u, 0x7F4A7C15u, 0xC6EF3720u, 0x165667B1u,
        0x85EBCA6Bu, 0x27D4EB2Fu, 0xB7E15163u, 0x9DDFEA76u,
        0xE08C1D64u, 0x4F1BBCDCu, 0xA3B19535u, 0x6C62272Eu,
        0xFBF44E5Fu, 0x1C6EF372u, 0xE12B4F97u, 0xC6D3A7E4u
    };

    std::vector<uint8_t> msg = pad_message(input);

    for (size_t i = 0; i < msg.size(); i += 4) {
        uint32_t block = le_bytes_to_u32(msg, i);

        for (int r = 0; r < 16; ++r) {
            uint32_t tA = rotl32(A + F(B,C,D) + block + RCON[r], (r%13)+1);
            uint32_t tB = rotl32(B + G(C,D,A) + block + RCON[(r+3)%16], (r%17)+1) + 0xA5A5A5A5u;
            uint32_t tC = rotl32(C + H(D,A,B) + block + RCON[(r+6)%16], (r%19)+1) ^ tA;
            uint32_t tD = rotl32(D + F(A,B,C) + block + RCON[(r+9)%16], (r%23)+1) + 0x5A5A5A5Au;

            // çapraz diffusion
            A = tA ^ (tB >> ((r%5)+1));
            B = tB ^ (tC << ((r%7)+1));
            C = tC ^ (tD >> ((r%11)+1));
            D = tD ^ (tA << ((r%13)+1));
        }

        // feed-forward
        A ^= block + 0xDEADBEEFu;
        B += (block ^ 0x0F0F0F0Fu);
        C ^= rotl32(block, 17);
        D += rotl32(block, 3);
    }

    for (int r = 0; r < 16; ++r) {
        A ^= rotl32(F(B,C,D) + RCON[r], (r%7)+1);
        B ^= rotl32(G(C,D,A) + RCON[(r+4)%16], (r%11)+1);
        C ^= rotl32(H(D,A,B) + RCON[(r+8)%16], (r%13)+1);
        D ^= rotl32(F(A,B,C) + RCON[(r+2)%16], (r%17)+1);

        A += (B ^ C);
        B += (C ^ D);
        C += (D ^ A);
        D += (A ^ B);
    }

    return to_hex(A, B, C, D);
}

int main() {
    std::string input;
    std::cout << "CipherA-128\n";
    std::cout << "Enter String: ";
    std::getline(std::cin, input);

    std::string hash = CipherA_128(input);
    std::cout << "CipherA-128 Hash: " << hash << "\n";
    return 0;  
}
