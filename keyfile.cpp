#include "keyfile.h"

#include <fstream>

namespace {

constexpr char MAGIC[4] = {'K', 'Y', 'K', '1'};
constexpr uint8_t TYPE_PUBLIC = 1;
constexpr uint8_t TYPE_SECRET = 2;

constexpr std::size_t HEADER_SIZE = 5;  // 4 magic + 1 type
constexpr std::size_t POLY_COEFF_BYTES = 2 * N;
constexpr std::size_t SECRET_PAYLOAD = K * POLY_COEFF_BYTES;
constexpr std::size_t PUBLIC_PAYLOAD = SEED_BYTES + SECRET_PAYLOAD;

void put_coeff(std::vector<uint8_t>& out, int c) {
    out.push_back(static_cast<uint8_t>(c & 0xFF));
    out.push_back(static_cast<uint8_t>((c >> 8) & 0xFF));
}

int get_coeff(const std::vector<uint8_t>& in, std::size_t& pos) {
    const int lo = in[pos];
    const int hi = in[pos + 1];
    pos += 2;
    return lo | (hi << 8);
}

std::vector<uint8_t> make_header(uint8_t type) {
    std::vector<uint8_t> out;
    out.insert(out.end(), {static_cast<uint8_t>(MAGIC[0]), static_cast<uint8_t>(MAGIC[1]),
                           static_cast<uint8_t>(MAGIC[2]), static_cast<uint8_t>(MAGIC[3])});
    out.push_back(type);
    return out;
}

bool check_header(const std::vector<uint8_t>& in, uint8_t type) {
    if (in.size() < HEADER_SIZE) {
        return false;
    }
    return in[0] == MAGIC[0] && in[1] == MAGIC[1] && in[2] == MAGIC[2] &&
           in[3] == MAGIC[3] && in[4] == type;
}

}  // namespace

std::vector<uint8_t> encode_public_key(const seed_t& d, const public_key_t& pk) {
    std::vector<uint8_t> out = make_header(TYPE_PUBLIC);
    out.insert(out.end(), d.begin(), d.end());
    for (int i = 0; i < K; ++i) {
        for (int c = 0; c < N; ++c) {
            put_coeff(out, pk.b[i][c]);
        }
    }
    return out;
}

bool decode_public_key(const std::vector<uint8_t>& blob, seed_t& d, public_key_t& pk) {
    if (!check_header(blob, TYPE_PUBLIC) || blob.size() != HEADER_SIZE + PUBLIC_PAYLOAD) {
        return false;
    }
    std::size_t pos = HEADER_SIZE;
    for (int i = 0; i < SEED_BYTES; ++i) {
        d[i] = blob[pos++];
    }
    for (int i = 0; i < K; ++i) {
        for (int c = 0; c < N; ++c) {
            int v = get_coeff(blob, pos);
            if (v < 0 || v >= Q) {
                return false;
            }
            pk.b[i][c] = v;
        }
    }
    pk.A = gen_matrix(d);
    return true;
}

std::vector<uint8_t> encode_secret_key(const secret_key_t& s) {
    std::vector<uint8_t> out = make_header(TYPE_SECRET);
    for (int i = 0; i < K; ++i) {
        for (int c = 0; c < N; ++c) {
            put_coeff(out, s[i][c]);
        }
    }
    return out;
}

bool decode_secret_key(const std::vector<uint8_t>& blob, secret_key_t& s) {
    if (!check_header(blob, TYPE_SECRET) || blob.size() != HEADER_SIZE + SECRET_PAYLOAD) {
        return false;
    }
    std::size_t pos = HEADER_SIZE;
    for (int i = 0; i < K; ++i) {
        for (int c = 0; c < N; ++c) {
            int v = get_coeff(blob, pos);
            if (v < 0 || v >= Q) {
                return false;
            }
            s[i][c] = v;
        }
    }
    return true;
}

bool save_public_key(const std::string& path, const seed_t& d, const public_key_t& pk) {
    std::ofstream f(path, std::ios::binary);
    if (!f) {
        return false;
    }
    const std::vector<uint8_t> blob = encode_public_key(d, pk);
    f.write(reinterpret_cast<const char*>(blob.data()),
            static_cast<std::streamsize>(blob.size()));
    return static_cast<bool>(f);
}

bool load_public_key(const std::string& path, seed_t& d, public_key_t& pk) {
    std::ifstream f(path, std::ios::binary);
    if (!f) {
        return false;
    }
    std::vector<uint8_t> blob((std::istreambuf_iterator<char>(f)),
                              std::istreambuf_iterator<char>());
    return decode_public_key(blob, d, pk);
}

bool save_secret_key(const std::string& path, const secret_key_t& s) {
    std::ofstream f(path, std::ios::binary);
    if (!f) {
        return false;
    }
    const std::vector<uint8_t> blob = encode_secret_key(s);
    f.write(reinterpret_cast<const char*>(blob.data()),
            static_cast<std::streamsize>(blob.size()));
    return static_cast<bool>(f);
}

bool load_secret_key(const std::string& path, secret_key_t& s) {
    std::ifstream f(path, std::ios::binary);
    if (!f) {
        return false;
    }
    std::vector<uint8_t> blob((std::istreambuf_iterator<char>(f)),
                              std::istreambuf_iterator<char>());
    return decode_secret_key(blob, s);
}
