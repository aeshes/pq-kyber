#ifndef RAND_H
#define RAND_H

#include <array>
#include <cstdint>
#include <random>

#include "polyvec.h"

constexpr int SEED_BYTES = 32;

using seed_t = std::array<uint8_t, SEED_BYTES>;

seed_t gen_seed();

poly_t random_polynomial(std::mt19937_64& gen);

poly_t uniform_polynomial(std::mt19937_64& gen);

matrix_t gen_matrix(const seed_t& seed);

polyvec_t generate_secret(const seed_t& seed);

polyvec_t generate_error(const seed_t& seed);

#endif // RAND_H
