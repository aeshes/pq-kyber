#include "rand.h"

#include <random>
#include <vector>

seed_t gen_seed() {
    static std::random_device rd;
    static std::mt19937_64 gen(rd());
    std::uniform_int_distribution<uint64_t> dist;

    seed_t seed{};
    for (std::size_t i = 0; i < seed.size(); i += 8) {
        const uint64_t r = dist(gen);
        for (int b = 0; b < 8 && i + b < seed.size(); ++b) {
            seed[i + b] = static_cast<uint8_t>(r >> (8 * b));
        }
    }
    return seed;
}

static int cbd_eta(std::mt19937_64& gen, std::uniform_int_distribution<int>& bit) {
    int a = 0;
    int b = 0;
    for (int j = 0; j < ETA; ++j) {
        a += bit(gen);
    }
    for (int j = 0; j < ETA; ++j) {
        b += bit(gen);
    }
    int x = a - b;
    x %= Q;
    if (x < 0) {
        x += Q;
    }
    return x;
}

poly_t random_polynomial(std::mt19937_64& gen) {
    std::uniform_int_distribution<int> bit(0, 1);
    poly_t f{};
    for (int i = 0; i < N; ++i) {
        f[i] = cbd_eta(gen, bit);
    }
    return f;
}

poly_t uniform_polynomial(std::mt19937_64& gen) {
    std::uniform_int_distribution<int> dist(0, Q - 1);
    poly_t f{};
    for (int i = 0; i < N; ++i) {
        f[i] = dist(gen);
    }
    return f;
}

static const uint8_t MATRIX_TAG = 0x00;
static const uint8_t SECRET_TAG = 0x01;
static const uint8_t ERROR_TAG  = 0x02;

static std::mt19937_64 seeded_from(const seed_t& seed, uint8_t tag) {
    std::vector<uint8_t> mix;
    mix.push_back(tag);
    mix.insert(mix.end(), seed.begin(), seed.end());
    std::seed_seq seq(mix.begin(), mix.end());
    return std::mt19937_64(seq);
}

static polyvec_t chi_vector(const seed_t& seed, uint8_t tag) {
    std::mt19937_64 gen = seeded_from(seed, tag);
    polyvec_t v{};
    for (int i = 0; i < K; ++i) {
        v[i] = random_polynomial(gen);
    }
    return v;
}

matrix_t gen_matrix(const seed_t& seed) {
    std::mt19937_64 gen = seeded_from(seed, MATRIX_TAG);
    matrix_t A{};
    for (int i = 0; i < K; ++i) {
        for (int j = 0; j < K; ++j) {
            A[i][j] = uniform_polynomial(gen);
        }
    }
    return A;
}

polyvec_t generate_secret(const seed_t& seed) {
    return chi_vector(seed, SECRET_TAG);
}

polyvec_t generate_error(const seed_t& seed) {
    return chi_vector(seed, ERROR_TAG);
}
