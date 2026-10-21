#include "hash.h"

namespace {

constexpr uint64_t RC[24] = {
    0x0000000000000001ULL, 0x0000000000008082ULL, 0x800000000000808aULL,
    0x8000000080008000ULL, 0x000000000000808bULL, 0x0000000080000001ULL,
    0x8000000080008081ULL, 0x8000000000008009ULL, 0x000000000000008aULL,
    0x0000000000000088ULL, 0x0000000080008009ULL, 0x000000008000000aULL,
    0x000000008000808bULL, 0x800000000000008bULL, 0x8000000000008089ULL,
    0x8000000000008003ULL, 0x8000000000008002ULL, 0x8000000000000080ULL,
    0x000000000000800aULL, 0x800000008000000aULL, 0x8000000080008081ULL,
    0x8000000000008080ULL, 0x0000000080000001ULL, 0x8000000080008008ULL};

const int RHO[5][5] = {
    {0, 36, 3, 41, 18},
    {1, 44, 10, 45, 2},
    {62, 6, 43, 15, 61},
    {28, 55, 25, 21, 56},
    {27, 20, 39, 8, 14},
};

uint64_t rotl64(uint64_t v, int n) {
    n &= 63;
    return n == 0 ? v : (v << n) | (v >> (64 - n));
}

void keccak_f1600(uint64_t A[25]) {
    for (int t = 0; t < 24; ++t) {
        uint64_t C[5];
        for (int x = 0; x < 5; ++x) {
            C[x] = A[x] ^ A[x + 5] ^ A[x + 10] ^ A[x + 15] ^ A[x + 20];
        }
        for (int x = 0; x < 5; ++x) {
            const uint64_t d = C[(x + 4) % 5] ^ rotl64(C[(x + 1) % 5], 1);
            for (int y = 0; y < 5; ++y) {
                A[x + 5 * y] ^= d;
            }
        }
        uint64_t B[25];
        for (int x = 0; x < 5; ++x) {
            for (int y = 0; y < 5; ++y) {
                const int sx = (x + 3 * y) % 5;
                B[x + 5 * y] = rotl64(A[sx + 5 * x], RHO[sx][x]);
            }
        }
        for (int y = 0; y < 5; ++y) {
            for (int x = 0; x < 5; ++x) {
                A[x + 5 * y] =
                    B[x + 5 * y] ^ (~B[(x + 1) % 5 + 5 * y] & B[(x + 2) % 5 + 5 * y]);
            }
        }
        A[0] ^= RC[t];
    }
}

}  // namespace

hash_t sha3_256(const uint8_t* data, std::size_t len) {
    constexpr std::size_t RATE = 136;
    uint64_t A[25] = {0};

    while (len >= RATE) {
        for (std::size_t j = 0; j < RATE; ++j) {
            A[j / 8] ^= static_cast<uint64_t>(data[j]) << (8 * (j % 8));
        }
        keccak_f1600(A);
        data += RATE;
        len -= RATE;
    }
    for (std::size_t j = 0; j < len; ++j) {
        A[j / 8] ^= static_cast<uint64_t>(data[j]) << (8 * (j % 8));
    }
    A[len / 8] ^= 0x06ULL << (8 * (len % 8));
    A[(RATE - 1) / 8] ^= 0x80ULL << (8 * ((RATE - 1) % 8));
    keccak_f1600(A);

    hash_t out{};
    for (std::size_t j = 0; j < out.size(); ++j) {
        out[j] = static_cast<uint8_t>(A[j / 8] >> (8 * (j % 8)));
    }
    return out;
}
