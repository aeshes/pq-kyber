#ifndef ENCRYPT_H
#define ENCRYPT_H

#include <array>
#include <utility>

#include "hash.h"
#include "keys.h"

using msg_t = std::array<uint8_t, N>;
using tag_t = hash_t;
using shared_key_t = hash_t;

struct ciphertext_t {
    polyvec_t c1;
    poly_t c2;
    tag_t tag;
};

struct kem_output {
    ciphertext_t ct;
    shared_key_t key;
};

poly_t encode_message(const msg_t& m);

msg_t decode_message(const poly_t& p);

ciphertext_t encrypt(const public_key_t& pk, const msg_t& m);

bool decrypt(const secret_key_t& s, const ciphertext_t& c, msg_t& m);

kem_output encaps(const public_key_t& pk);

shared_key_t decaps(const secret_key_t& s, const ciphertext_t& ct);

#endif // ENCRYPT_H
