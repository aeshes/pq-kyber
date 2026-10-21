#ifndef POLYVEC_H
#define POLYVEC_H

#include <array>

#include "ntt.h"

using polyvec_t = std::array<poly_t, K>;
using matrix_t = std::array<std::array<poly_t, K>, K>;

polyvec_t add(const polyvec_t& a, const polyvec_t& b);

poly_t add(const poly_t& a, const poly_t& b);

polyvec_t mult(const polyvec_t& v, const matrix_t& A);

polyvec_t mult_transpose(const polyvec_t& v, const matrix_t& A);

poly_t dot(const polyvec_t& a, const polyvec_t& b);

#endif // POLYVEC_H
