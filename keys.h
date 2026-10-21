#ifndef KEYS_H
#define KEYS_H

#include "polyvec.h"
#include "rand.h"

using secret_key_t = polyvec_t;

struct public_key_t {
    matrix_t A;
    polyvec_t b;
};

secret_key_t generate_secret_key(const seed_t& z);

public_key_t generate_public_key(const seed_t& d, const seed_t& z, const secret_key_t& s);

#endif // KEYS_H
