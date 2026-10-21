#include "keys.h"

secret_key_t generate_secret_key(const seed_t& z) {
    return generate_secret(z);
}

public_key_t generate_public_key(const seed_t& d, const seed_t& z, const secret_key_t& s) {
    const matrix_t A = gen_matrix(d);
    const polyvec_t e = generate_error(z);
    return public_key_t{A, add(mult(s, A), e)};
}
