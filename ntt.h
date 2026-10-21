#ifndef NTT_H
#define NTT_H

#include <array>
#include <cstdint>
#include "params.h"

using poly_t = std::array<int, N>;

poly_t mult(const poly_t& f, const poly_t& g);

#endif