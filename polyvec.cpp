#include "polyvec.h"

polyvec_t add(const polyvec_t& a, const polyvec_t& b) {
    polyvec_t r{};
    for (int i = 0; i < K; ++i) {
        for (int j = 0; j < N; ++j) {
            r[i][j] = a[i][j] + b[i][j];
            if (r[i][j] >= Q) {
                r[i][j] -= Q;
            }
        }
    }
    return r;
}

poly_t add(const poly_t& a, const poly_t& b) {
    poly_t r{};
    for (int i = 0; i < N; ++i) {
        r[i] = a[i] + b[i];
        if (r[i] >= Q) {
            r[i] -= Q;
        }
    }
    return r;
}

polyvec_t mult(const polyvec_t& v, const matrix_t& A) {
    polyvec_t r{};
    for (int j = 0; j < K; ++j) {
        for (int i = 0; i < K; ++i) {
            const poly_t t = mult(v[i], A[i][j]);
            for (int c = 0; c < N; ++c) {
                r[j][c] += t[c];
                if (r[j][c] >= Q) {
                    r[j][c] -= Q;
                }
            }
        }
    }
    return r;
}

polyvec_t mult_transpose(const polyvec_t& v, const matrix_t& A) {
    polyvec_t r{};
    for (int j = 0; j < K; ++j) {
        for (int i = 0; i < K; ++i) {
            const poly_t t = mult(v[i], A[j][i]);
            for (int c = 0; c < N; ++c) {
                r[j][c] += t[c];
                if (r[j][c] >= Q) {
                    r[j][c] -= Q;
                }
            }
        }
    }
    return r;
}

poly_t dot(const polyvec_t& a, const polyvec_t& b) {
    poly_t r{};
    for (int i = 0; i < K; ++i) {
        const poly_t t = mult(a[i], b[i]);
        for (int c = 0; c < N; ++c) {
            r[c] += t[c];
            if (r[c] >= Q) {
                r[c] -= Q;
            }
        }
    }
    return r;
}
