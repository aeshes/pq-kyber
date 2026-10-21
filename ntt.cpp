#include "ntt.h"

static int brv7(int x) {
    int y = 0;
    for (int i = 0; i < 7; ++i) {
        y = (y << 1) | (x & 1); x >>= 1;
    }
    return y;
}

static int mod_q(int x) {
    x %= Q;
    if (x < 0) {
        x += Q;
    }
    return x;
}

static const std::array<int, 128> ZETAS = [] {
    std::array<int, 128> z{};
    for (int i = 0; i < 128; ++i) {
        int base = ROOT;
        int e = brv7(i);
        int r = 1;
        while (e > 0) {
            if (e & 1) {
                r = r * base % Q;
            }
            base = base * base % Q;
            e >>= 1;
        }
        z[i] = r;
    }
    return z;
}();

static poly_t ntt(const poly_t& in) {
    poly_t a = in;
    int k = 1;
    for (int len = 128; len >= 2; len >>= 1) {
        for (int start = 0; start < N; start += 2 * len) {
            int zeta = ZETAS[k++];
            for (int j = start; j < start + len; ++j) {
                int t = (zeta) * a[j + len] % Q;
                a[j + len] = mod_q(a[j] - t);
                a[j]       = mod_q(a[j] + t);
            }
        }
    }
    return a;
}

static poly_t inverse_ntt(const poly_t& in) {
    poly_t a = in;
    int k = 127;
    for (int len = 2; len <= 128; len <<= 1) {
        for (int start = 0; start < N; start += 2 * len) {
            int zeta = ZETAS[k--];
            for (int j = start; j < start + len; ++j) {
                int t = a[j];
                a[j]       = mod_q(t + a[j + len]);
                a[j + len] = mod_q((a[j + len]) - t) * zeta % Q;
            }
        }
    }
    constexpr int n_inv = 7621;
    for (int i = 0; i < N; ++i)
        a[i] = a[i] * n_inv % Q;
    return a;
}

static poly_t pointwise_mul(const poly_t& a, const poly_t& b) {
    poly_t out{};
    for (int j = 0; j < 128; ++j) {
        int zeta = ZETAS[64 + j / 2];
        if (j & 1) {
            zeta = Q - zeta;
        }
        const int a0 = a[2 * j];
        const int a1 = a[2 * j + 1];
        const int b0 = b[2 * j];
        const int b1 = b[2 * j + 1];
        const int r0 = a0 * b0 + (a1 * b1 % Q) * zeta;
        const int r1 = a0 * b1 + a1 * b0;
        out[2 * j]     = r0 % Q;
        out[2 * j + 1] = r1 % Q;
    }
    return out;
}

poly_t mult(const poly_t& f, const poly_t& g) {
    poly_t fa = ntt(f);
    poly_t ga = ntt(g);
    poly_t h  = pointwise_mul(fa, ga);
    return inverse_ntt(h);
}