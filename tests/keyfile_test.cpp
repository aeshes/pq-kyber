#include <gtest/gtest.h>

#include "encrypt.h"
#include "keyfile.h"

#include <cstdio>
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

}  // namespace

TEST(KeyFile, Sizes) {
    const seed_t d = gen_seed();
    const seed_t z = gen_seed();
    const secret_key_t s = generate_secret_key(z);
    const public_key_t pk = generate_public_key(d, z, s);
    EXPECT_EQ(encode_public_key(d, pk).size(), 5u + 32u + 2u * 256u * K);
    EXPECT_EQ(encode_secret_key(s).size(), 5u + 2u * 256u * K);
}

TEST(KeyFile, PublicKeyBlobRoundTrip) {
    const seed_t d = gen_seed();
    const seed_t z = gen_seed();
    const secret_key_t s = generate_secret_key(z);
    const public_key_t pk = generate_public_key(d, z, s);

    const std::vector<uint8_t> blob = encode_public_key(d, pk);
    seed_t d2{};
    public_key_t pk2{};
    ASSERT_TRUE(decode_public_key(blob, d2, pk2));
    EXPECT_EQ(d, d2);
    EXPECT_EQ(pk2.A, pk.A);
    EXPECT_EQ(pk2.b, pk.b);
}

TEST(KeyFile, SecretKeyBlobRoundTrip) {
    const seed_t d = gen_seed();
    const secret_key_t s = generate_secret_key(d);

    const std::vector<uint8_t> blob = encode_secret_key(s);
    secret_key_t s2{};
    ASSERT_TRUE(decode_secret_key(blob, s2));
    EXPECT_EQ(s2, s);
}

TEST(KeyFile, KeysUsableAfterRoundTrip) {
    std::mt19937_64 rng(31);
    const seed_t d = gen_seed();
    const seed_t z = gen_seed();
    const secret_key_t s = generate_secret_key(z);
    const public_key_t pk = generate_public_key(d, z, s);

    const std::vector<uint8_t> pk_blob = encode_public_key(d, pk);
    const std::vector<uint8_t> sk_blob = encode_secret_key(s);

    seed_t d2{};
    public_key_t pk2{};
    secret_key_t s2{};
    ASSERT_TRUE(decode_public_key(pk_blob, d2, pk2));
    ASSERT_TRUE(decode_secret_key(sk_blob, s2));

    for (int t = 0; t < 5; ++t) {
        const msg_t m = random_msg(rng);
        msg_t out{};
        ASSERT_TRUE(decrypt(s2, encrypt(pk2, m), out)) << "trial " << t;
        EXPECT_EQ(out, m) << "trial " << t;
    }
}

TEST(KeyFile, WrongTypeRejected) {
    const seed_t d = gen_seed();
    const seed_t z = gen_seed();
    const secret_key_t s = generate_secret_key(z);
    const public_key_t pk = generate_public_key(d, z, s);

    seed_t d2{};
    public_key_t pk2{};
    secret_key_t s2{};
    EXPECT_FALSE(decode_public_key(encode_secret_key(s), d2, pk2));
    EXPECT_FALSE(decode_secret_key(encode_public_key(d, pk), s2));
}

TEST(KeyFile, TruncatedAndTamperedRejected) {
    const seed_t d = gen_seed();
    const secret_key_t s = generate_secret_key(d);

    std::vector<uint8_t> blob = encode_secret_key(s);
    secret_key_t s2{};
    blob.pop_back();
    EXPECT_FALSE(decode_secret_key(blob, s2));

    blob = encode_secret_key(s);
    blob[0] ^= 0xFF;
    EXPECT_FALSE(decode_secret_key(blob, s2));

    blob = encode_secret_key(s);
    blob[5 + 2 * 255] = 0xFF;
    blob[5 + 2 * 255 + 1] = 0xFF;
    EXPECT_FALSE(decode_secret_key(blob, s2));
}

TEST(KeyFile, FileRoundTrip) {
    const seed_t d = gen_seed();
    const seed_t z = gen_seed();
    const secret_key_t s = generate_secret_key(z);
    const public_key_t pk = generate_public_key(d, z, s);

    const std::string sk_path = "/tmp/kyber_sk_test.bin";
    const std::string pk_path = "/tmp/kyber_pk_test.bin";
    ASSERT_TRUE(save_secret_key(sk_path, s));
    ASSERT_TRUE(save_public_key(pk_path, d, pk));

    seed_t d2{};
    public_key_t pk2{};
    secret_key_t s2{};
    ASSERT_TRUE(load_secret_key(sk_path, s2));
    ASSERT_TRUE(load_public_key(pk_path, d2, pk2));
    EXPECT_EQ(s2, s);
    EXPECT_EQ(d2, d);
    EXPECT_EQ(pk2.A, pk.A);
    EXPECT_EQ(pk2.b, pk.b);

    std::remove(sk_path.c_str());
    std::remove(pk_path.c_str());
}
