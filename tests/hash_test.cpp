#include <gtest/gtest.h>

#include "hash.h"

#include <string>

namespace {

std::string to_hex(const hash_t& h) {
    static const char* D = "0123456789abcdef";
    std::string s;
    for (uint8_t b : h) {
        s.push_back(D[b >> 4]);
        s.push_back(D[b & 0xF]);
    }
    return s;
}

hash_t hash_of(const std::string& str) {
    return sha3_256(reinterpret_cast<const uint8_t*>(str.data()), str.size());
}

}  // namespace

TEST(Sha3_256, EmptyString) {
    EXPECT_EQ(to_hex(hash_of("")),
              "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a");
}

TEST(Sha3_256, Abc) {
    EXPECT_EQ(to_hex(hash_of("abc")),
              "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532");
}

TEST(Sha3_256, MultiBlock200A) {
    EXPECT_EQ(to_hex(hash_of(std::string(200, 'a'))),
              "cce34485baf2bf2aca99b94833892a4f52896d3d153f7b840cc4f9fe695f1387");
}

TEST(Sha3_256, DeterministicAndDistinctAcrossBlockBoundary) {
    std::string a(135, 'x');
    std::string b(136, 'x');
    EXPECT_EQ(hash_of(a), hash_of(std::string(135, 'x')));
    EXPECT_NE(hash_of(a), hash_of(b));
    hash_t before = hash_of(a);
    a.back() ^= 0x01;
    EXPECT_NE(hash_of(a), before);
}

TEST(Sha3_256, Avalanche) {
    std::string a = "hello kyber";
    std::string b = "hello kyber2";
    hash_t ha = hash_of(a);
    hash_t hb = hash_of(b);
    int diff = 0;
    for (int i = 0; i < 32; ++i) {
        diff += __builtin_popcount(ha[i] ^ hb[i]);
    }
    EXPECT_GT(diff, 60);
}
