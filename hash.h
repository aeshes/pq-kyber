#ifndef HASH_H
#define HASH_H

#include <array>
#include <cstddef>
#include <cstdint>

using hash_t = std::array<uint8_t, 32>;

hash_t sha3_256(const uint8_t* data, std::size_t len);

#endif // HASH_H
