#ifndef KEYFILE_H
#define KEYFILE_H

#include <cstdint>
#include <string>
#include <vector>

#include "keys.h"

std::vector<uint8_t> encode_public_key(const seed_t& d, const public_key_t& pk);

bool decode_public_key(const std::vector<uint8_t>& blob, seed_t& d, public_key_t& pk);

std::vector<uint8_t> encode_secret_key(const secret_key_t& s);

bool decode_secret_key(const std::vector<uint8_t>& blob, secret_key_t& s);

bool save_public_key(const std::string& path, const seed_t& d, const public_key_t& pk);

bool load_public_key(const std::string& path, seed_t& d, public_key_t& pk);

bool save_secret_key(const std::string& path, const secret_key_t& s);

bool load_secret_key(const std::string& path, secret_key_t& s);

#endif // KEYFILE_H
