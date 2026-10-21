#include <gtest/gtest.h>

#include "ntt.h"

#include <random>
#include <vector>

namespace {

poly_t zero_poly() {
    return poly_t{};
}

poly_t from_coeffs(const std::vector<int>& coeffs) {
    poly_t p{};
    for (std::size_t i = 0; i < coeffs.size() && i < poly_t{}.size(); ++i) {
        p[i] = coeffs[i];
    }
    return p;
}

poly_t monomial(int deg, int coeff = 1) {
    poly_t p{};
    p[deg] = coeff;
    return p;
}

poly_t one_poly() {
    return monomial(0, 1);
}

int norm(int x) {
    x %= Q;
    if (x < 0) {
        x += Q;
    }
    return x;
}

poly_t add_mod(const poly_t& a, const poly_t& b) {
    poly_t r{};
    for (int i = 0; i < N; ++i) {
        r[i] = norm(a[i] + b[i]);
    }
    return r;
}

poly_t naive_mult(const poly_t& f, const poly_t& g) {
    poly_t h{};
    for (int i = 0; i < N; ++i) {
        for (int j = 0; j < N; ++j) {
            const long long v = static_cast<long long>(norm(f[i])) * norm(g[j]);
            const int k = i + j;
            if (k < N) {
                h[k] = static_cast<int>((h[k] + v) % Q);
            } else {
                h[k - N] = static_cast<int>((h[k - N] - v) % Q);
            }
        }
    }
    for (int i = 0; i < N; ++i) {
        h[i] = norm(h[i]);
    }
    return h;
}

poly_t random_poly(std::mt19937& rng, int min_coeff = 0, int max_coeff = Q - 1) {
    std::uniform_int_distribution<int> dist(min_coeff, max_coeff);
    poly_t p;
    for (int i = 0; i < N; ++i) {
        p[i] = dist(rng);
    }
    return p;
}

}  // namespace

TEST(NttMult, ZeroAnnihilates) {
    std::mt19937 rng(42);
    const poly_t f = random_poly(rng);
    const poly_t z = zero_poly();
    EXPECT_EQ(mult(z, z), z);
    EXPECT_EQ(mult(z, f), z);
    EXPECT_EQ(mult(f, z), z);
}

TEST(NttMult, OneIsIdentity) {
    std::mt19937 rng(7);
    const poly_t f = random_poly(rng);
    const poly_t one = monomial(0, 1);
    EXPECT_EQ(mult(one, f), f);
    EXPECT_EQ(mult(f, one), f);
}

TEST(NttMult, ConstantsMultiplyModQ) {
    const poly_t a = monomial(0, 7680);
    const poly_t b = monomial(0, 7680);
    EXPECT_EQ(mult(a, b), monomial(0, 1));
    EXPECT_EQ(mult(a, one_poly()), monomial(0, Q - 1));
    EXPECT_EQ(mult(monomial(0, 100), monomial(0, 77)), monomial(0, 7700 % Q));
}

TEST(NttMult, MatchesSchoolbookFixed) {
    const poly_t f = from_coeffs({1, 2, 3});
    const poly_t g = from_coeffs({4, 5, 6});
    EXPECT_EQ(mult(f, g), naive_mult(f, g));

    const poly_t f2 = from_coeffs({7680, 7680, 7680});
    const poly_t g2 = from_coeffs({1, 7681 / 2, 7679});
    EXPECT_EQ(mult(f2, g2), naive_mult(f2, g2));
}

TEST(NttMult, MatchesSchoolbookRandom) {
    std::mt19937 rng(2026);
    for (int t = 0; t < 5; ++t) {
        const poly_t f = random_poly(rng);
        const poly_t g = random_poly(rng);
        EXPECT_EQ(mult(f, g), naive_mult(f, g)) << "trial " << t;
    }
}

TEST(NttMult, NegacyclicWraparound) {
    const poly_t x255 = monomial(255);
    const poly_t x = monomial(1);
    EXPECT_EQ(mult(x255, x), monomial(0, Q - 1));
    EXPECT_EQ(mult(x255, x255), monomial(254, Q - 1));
}

TEST(NttMult, Commutative) {
    std::mt19937 rng(123);
    const poly_t f = random_poly(rng);
    const poly_t g = random_poly(rng);
    EXPECT_EQ(mult(f, g), mult(g, f));
}

TEST(NttMult, Distributive) {
    std::mt19937 rng(321);
    const poly_t f = random_poly(rng);
    const poly_t g = random_poly(rng);
    const poly_t h = random_poly(rng);
    EXPECT_EQ(mult(f, add_mod(g, h)), add_mod(mult(f, g), mult(f, h)));
}

TEST(NttMult, Associative) {
    std::mt19937 rng(555);
    const poly_t f = random_poly(rng, 0, 100);
    const poly_t g = random_poly(rng, 0, 100);
    const poly_t h = random_poly(rng, 0, 100);
    EXPECT_EQ(mult(mult(f, g), h), mult(f, mult(g, h)));
}

TEST(NttMult, OutputInCanonicalRange) {
    std::mt19937 rng(999);
    const poly_t f = random_poly(rng);
    const poly_t g = random_poly(rng);
    const poly_t r = mult(f, g);
    for (int i = 0; i < N; ++i) {
        ASSERT_GE(r[i], 0) << "index " << i;
        ASSERT_LT(r[i], Q) << "index " << i;
    }
}
