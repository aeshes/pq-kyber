#include <gtest/gtest.h>

#include "encrypt.h"

#include <random>

namespace {

msg_t random_msg(std::mt19937_64& rng) {
    std::uniform_int_distribution<int> d(0, 1);
    msg_t m;
    for (int i = 0; i < N; ++i) {
        m[i] = static_cast<uint8_t>(d(rng));
    }
    return m;
}

msg_t pattern_msg(int kind) {
    msg_t m{};
    for (int i = 0; i < N; ++i) {
        if (kind == 1) {
            m[i] = 1;
        } else if (kind == 2) {
            m[i] = static_cast<uint8_t>(i % 2);
        } else if (kind == 3) {
            m[i] = static_cast<uint8_t>((i / 8) % 2);
        }
    }
    return m;
}

bool roundtrip_ok(const public_key_t& pk, const secret_key_t& s, const msg_t& m) {
    msg_t out{};
    return decrypt(s, encrypt(pk, m), out) && out == m;
}

}  // namespace

TEST(EncodeDecode, DecodeInvertsEncode) {
    std::mt19937_64 rng(11);
    for (int t = 0; t < 10; ++t) {
        const msg_t m = random_msg(rng);
        EXPECT_EQ(decode_message(encode_message(m)), m) << "trial " << t;
    }
}

TEST(EncodeDecode, EncodedCoefficientsAreZeroOrHalfQ) {
    std::mt19937_64 rng(13);
    const msg_t m = random_msg(rng);
    const poly_t p = encode_message(m);
    for (int i = 0; i < N; ++i) {
        ASSERT_TRUE(p[i] == 0 || p[i] == (Q + 1) / 2) << "index " << i;
        ASSERT_EQ(p[i], m[i] * ((Q + 1) / 2)) << "index " << i;
    }
}

TEST(EncodeDecode, DecodeThresholds) {
    struct Case {
        int value;
        uint8_t expected;
    } cases[] = {
        {0, 0},
        {1, 0},
        {Q / 4, 0},
        {Q / 4 + 1, 1},
        {(Q + 1) / 2, 1},
        {Q - Q / 4 - 1, 1},
        {Q - Q / 4, 0},
        {Q - 1, 0},
    };
    poly_t p{};
    msg_t expected{};
    for (std::size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        p[i] = cases[i].value;
        expected[i] = cases[i].expected;
    }
    const msg_t got = decode_message(p);
    for (std::size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        EXPECT_EQ(got[i], expected[i]) << "value " << cases[i].value;
    }
}

TEST(EncodeDecode, DecodeToleratesNoiseBelowThreshold) {
    std::mt19937_64 rng(17);
    std::uniform_int_distribution<int> noise(-Q / 4 + 50, Q / 4 - 50);
    for (int t = 0; t < 20; ++t) {
        const msg_t m = random_msg(rng);
        const poly_t enc = encode_message(m);
        poly_t u{};
        for (int i = 0; i < N; ++i) {
            int v = enc[i] + noise(rng);
            v %= Q;
            if (v < 0) {
                v += Q;
            }
            u[i] = v;
        }
        EXPECT_EQ(decode_message(u), m) << "trial " << t;
    }
}

TEST(Encrypt, RoundTripRandomMessages) {
    std::mt19937_64 rng(1);
    for (int t = 0; t < 25; ++t) {
        const seed_t d = gen_seed();
        const seed_t z = gen_seed();
        const secret_key_t s = generate_secret_key(z);
        const public_key_t pk = generate_public_key(d, z, s);
        const msg_t m = random_msg(rng);
        EXPECT_TRUE(roundtrip_ok(pk, s, m)) << "trial " << t;
    }
}

TEST(Encrypt, RoundTripPatternMessages) {
    for (int kind = 0; kind <= 3; ++kind) {
        const seed_t d = gen_seed();
        const seed_t z = gen_seed();
        const secret_key_t s = generate_secret_key(z);
        const public_key_t pk = generate_public_key(d, z, s);
        const msg_t m = pattern_msg(kind);
        EXPECT_TRUE(roundtrip_ok(pk, s, m)) << "pattern " << kind;
    }
}

TEST(Encrypt, CiphertextIsRandomized) {
    const seed_t d = gen_seed();
    const seed_t z = gen_seed();
    const secret_key_t s = generate_secret_key(z);
    const public_key_t pk = generate_public_key(d, z, s);
    const msg_t m = pattern_msg(0);
    const ciphertext_t c1 = encrypt(pk, m);
    const ciphertext_t c2 = encrypt(pk, m);
    EXPECT_NE(c1.c1, c2.c1);
    EXPECT_NE(c1.c2, c2.c2);
    msg_t o1{}, o2{};
    ASSERT_TRUE(decrypt(s, c1, o1));
    ASSERT_TRUE(decrypt(s, c2, o2));
    EXPECT_EQ(o1, o2);
}

TEST(Encrypt, DecryptIsDeterministic) {
    const seed_t d = gen_seed();
    const seed_t z = gen_seed();
    const secret_key_t s = generate_secret_key(z);
    const public_key_t pk = generate_public_key(d, z, s);
    msg_t m{};
    for (int i = 0; i < N; ++i) {
        m[i] = static_cast<uint8_t>(i % 2);
    }
    const ciphertext_t c = encrypt(pk, m);
    msg_t r1{}, r2{};
    ASSERT_TRUE(decrypt(s, c, r1));
    ASSERT_TRUE(decrypt(s, c, r2));
    EXPECT_EQ(r1, r2);
    EXPECT_EQ(r1, m);
}

TEST(Decrypt, WrongKeyDoesNotRecoverMessage) {
    const seed_t d1 = gen_seed();
    const seed_t z1 = gen_seed();
    const seed_t z2 = gen_seed();
    const secret_key_t s1 = generate_secret_key(z1);
    const secret_key_t s2 = generate_secret_key(z2);
    const public_key_t pk = generate_public_key(d1, z1, s1);
    const msg_t m = pattern_msg(1);
    const ciphertext_t c = encrypt(pk, m);
    msg_t wrong{};
    if (decrypt(s2, c, wrong)) {
        int diff = 0;
        for (int i = 0; i < N; ++i) {
            diff += wrong[i] != m[i];
        }
        EXPECT_GT(diff, 10);
    }
    SUCCEED();
}

TEST(Decrypt, RejectsForgedZeroCiphertext) {
    const seed_t z = gen_seed();
    const secret_key_t s = generate_secret_key(z);
    ciphertext_t c{};
    msg_t out{};
    EXPECT_FALSE(decrypt(s, c, out));
}

TEST(Decrypt, RejectsBitFlipInC2) {
    const seed_t d = gen_seed();
    const seed_t z = gen_seed();
    const secret_key_t s = generate_secret_key(z);
    const public_key_t pk = generate_public_key(d, z, s);
    const msg_t m = pattern_msg(1);
    ciphertext_t c = encrypt(pk, m);
    int v = c.c2[7] + (Q + 1) / 2;
    if (v >= Q) {
        v -= Q;
    }
    c.c2[7] = v;
    msg_t out{};
    EXPECT_FALSE(decrypt(s, c, out));
}

TEST(Decrypt, RejectsTamperedTag) {
    const seed_t d = gen_seed();
    const seed_t z = gen_seed();
    const secret_key_t s = generate_secret_key(z);
    const public_key_t pk = generate_public_key(d, z, s);
    const msg_t m = pattern_msg(2);
    ciphertext_t c = encrypt(pk, m);
    c.tag[0] ^= 0x01;
    msg_t out{};
    EXPECT_FALSE(decrypt(s, c, out));
}

TEST(Decrypt, RejectsSwappedTagBetweenCiphertexts) {
    const seed_t d = gen_seed();
    const seed_t z = gen_seed();
    const secret_key_t s = generate_secret_key(z);
    const public_key_t pk = generate_public_key(d, z, s);
    ciphertext_t ca = encrypt(pk, pattern_msg(1));
    ciphertext_t cb = encrypt(pk, pattern_msg(2));
    const tag_t ta = ca.tag;
    ca.tag = cb.tag;
    cb.tag = ta;
    msg_t out{};
    EXPECT_FALSE(decrypt(s, ca, out));
    EXPECT_FALSE(decrypt(s, cb, out));
}

namespace {

std::pair<secret_key_t, public_key_t> make_keypair() {
    const seed_t d = gen_seed();
    const seed_t z = gen_seed();
    const secret_key_t s = generate_secret_key(z);
    const public_key_t pk = generate_public_key(d, z, s);
    return {s, pk};
}

int key_bits(const shared_key_t& k) {
    int c = 0;
    for (uint8_t b : k) {
        c += __builtin_popcount(b);
    }
    return c;
}

}  // namespace

TEST(Kem, EncapsDecapsAgree) {
    for (int t = 0; t < 10; ++t) {
        auto [s, pk] = make_keypair();
        const kem_output e = encaps(pk);
        const shared_key_t k2 = decaps(s, e.ct);
        EXPECT_EQ(e.key, k2) << "trial " << t;
    }
}

TEST(Kem, KeysDistinctPerEncapsulation) {
    auto [s, pk] = make_keypair();
    const kem_output e1 = encaps(pk);
    const kem_output e2 = encaps(pk);
    EXPECT_NE(e1.key, e2.key);
    EXPECT_NE(e1.ct.c1, e2.ct.c1);
}

TEST(Kem, KeyHasReasonableEntropy) {
    auto [s, pk] = make_keypair();
    const kem_output e = encaps(pk);
    const int ones = key_bits(e.key);
    EXPECT_GT(ones, 40);
    EXPECT_LT(ones, 216);
}

TEST(Kem, RejectionKeyDeterministicAndDifferentFromReal) {
    auto [s, pk] = make_keypair();
    const kem_output e = encaps(pk);
    ciphertext_t tampered = e.ct;
    int v = tampered.c2[5] + (Q + 1) / 2;
    if (v >= Q) {
        v -= Q;
    }
    tampered.c2[5] = v;
    const shared_key_t r1 = decaps(s, tampered);
    const shared_key_t r2 = decaps(s, tampered);
    EXPECT_EQ(r1, r2);
    EXPECT_NE(r1, e.key);
    EXPECT_NE(r1, shared_key_t{});
}

TEST(Kem, RejectionKeysDifferAcrossCiphertexts) {
    auto [s, pk] = make_keypair();
    const kem_output e1 = encaps(pk);
    const kem_output e2 = encaps(pk);
    ciphertext_t t1 = e1.ct;
    ciphertext_t t2 = e2.ct;
    t1.c2[0] = (t1.c2[0] + 1) % Q;
    t2.c2[0] = (t2.c2[0] + 1) % Q;
    EXPECT_NE(decaps(s, t1), decaps(s, t2));
}

TEST(Kem, DifferentSecretKeysGiveDifferentRejectionKeys) {
    auto [s1, pk] = make_keypair();
    auto [s2, pk2] = make_keypair();
    (void)pk2;
    const kem_output e = encaps(pk);
    ciphertext_t bad = e.ct;
    bad.tag[0] ^= 0xFF;
    EXPECT_NE(decaps(s1, bad), decaps(s2, bad));
}
