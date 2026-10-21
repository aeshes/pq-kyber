#include "encrypt.h"

#include <cstring>
#include <random>
#include <vector>

namespace {

void push_u16(std::vector<uint8_t>& v, int x) {
    v.push_back(static_cast<uint8_t>(x & 0xFF));
    v.push_back(static_cast<uint8_t>((x >> 8) & 0xFF));
}

std::array<uint8_t, 32> pack_msg(const msg_t& m) {
    std::array<uint8_t, 32> out{};
    for (int i = 0; i < N / 8; ++i) {
        uint8_t byte = 0;
        for (int b = 0; b < 8; ++b) {
            byte |= static_cast<uint8_t>(m[8 * i + b] & 1) << b;
        }
        out[i] = byte;
    }
    return out;
}

void push_poly(std::vector<uint8_t>& v, const poly_t& p) {
    for (int c = 0; c < N; ++c) {
        push_u16(v, p[c]);
    }
}

std::vector<uint8_t> ct_material(const ciphertext_t& c) {
    std::vector<uint8_t> v;
    for (int i = 0; i < K; ++i) {
        push_poly(v, c.c1[i]);
    }
    push_poly(v, c.c2);
    return v;
}

shared_key_t kem_derive(const char* domain, const std::vector<uint8_t>& secret,
                        const std::vector<uint8_t>& ctmat) {
    std::vector<uint8_t> buf(domain, domain + std::strlen(domain));
    buf.insert(buf.end(), secret.begin(), secret.end());
    buf.insert(buf.end(), ctmat.begin(), ctmat.end());
    return sha3_256(buf.data(), buf.size());
}

tag_t compute_tag(const msg_t& m, const polyvec_t& c1, const poly_t& c2) {
    static const char LABEL[] = "kyber-pke-integrity-v1";
    std::vector<uint8_t> buf;
    buf.insert(buf.end(), LABEL, LABEL + sizeof(LABEL) - 1);
    const std::array<uint8_t, 32> packed = pack_msg(m);
    buf.insert(buf.end(), packed.begin(), packed.end());
    for (int i = 0; i < K; ++i) {
        push_poly(buf, c1[i]);
    }
    push_poly(buf, c2);
    return sha3_256(buf.data(), buf.size());
}

bool tag_equal(const tag_t& a, const tag_t& b) {
    uint8_t acc = 0;
    for (std::size_t i = 0; i < a.size(); ++i) {
        acc |= a[i] ^ b[i];
    }
    return acc == 0;
}

}  // namespace

poly_t encode_message(const msg_t& m) {
    poly_t p{};
    for (int i = 0; i < N; ++i) {
        p[i] = (m[i] & 1) * ((Q + 1) / 2);
    }
    return p;
}

msg_t decode_message(const poly_t& p) {
    msg_t m{};
    for (int i = 0; i < N; ++i) {
        int x = p[i];
        if (x > (Q + 1) / 2) {
            x -= Q;
        }
        m[i] = ((x < 0 ? -x : x) > Q / 4) ? 1 : 0;
    }
    return m;
}

ciphertext_t encrypt(const public_key_t& pk, const msg_t& m) {
    std::random_device rd;
    std::mt19937_64 gen((static_cast<uint64_t>(rd()) << 32) | rd());

    polyvec_t r{};
    polyvec_t e1{};
    for (int i = 0; i < K; ++i) {
        r[i] = random_polynomial(gen);
        e1[i] = random_polynomial(gen);
    }
    const poly_t e2 = random_polynomial(gen);

    ciphertext_t c;
    c.c1 = add(mult_transpose(r, pk.A), e1);
    c.c2 = add(add(dot(r, pk.b), e2), encode_message(m));
    c.tag = compute_tag(m, c.c1, c.c2);
    return c;
}

bool decrypt(const secret_key_t& s, const ciphertext_t& c, msg_t& m) {
    const poly_t cs = dot(c.c1, s);
    poly_t u{};
    for (int i = 0; i < N; ++i) {
        int v = c.c2[i] - cs[i];
        if (v < 0) {
            v += Q;
        }
        u[i] = v;
    }
    const msg_t candidate = decode_message(u);
    if (!tag_equal(c.tag, compute_tag(candidate, c.c1, c.c2))) {
        m = msg_t{};
        return false;
    }
    m = candidate;
    return true;
}

kem_output encaps(const public_key_t& pk) {
    std::random_device rd;
    std::mt19937_64 gen((static_cast<uint64_t>(rd()) << 32) | rd());
    std::uniform_int_distribution<uint64_t> dist;

    msg_t m{};
    for (int w = 0; w < N / 64; ++w) {
        const uint64_t x = dist(gen);
        for (int b = 0; b < 64; ++b) {
            m[64 * w + b] = static_cast<uint8_t>((x >> b) & 1);
        }
    }

    kem_output out;
    const std::array<uint8_t, 32> packed = pack_msg(m);
    out.ct = encrypt(pk, m);
    out.key = kem_derive("kyber-kem-key-v1",
                         std::vector<uint8_t>(packed.begin(), packed.end()),
                         ct_material(out.ct));
    return out;
}

shared_key_t decaps(const secret_key_t& s, const ciphertext_t& ct) {
    const std::vector<uint8_t> ctmat = ct_material(ct);
    msg_t m{};
    if (decrypt(s, ct, m)) {
        const std::array<uint8_t, 32> packed = pack_msg(m);
        return kem_derive("kyber-kem-key-v1",
                          std::vector<uint8_t>(packed.begin(), packed.end()), ctmat);
    }
    std::vector<uint8_t> secret;
    for (int i = 0; i < K; ++i) {
        push_poly(secret, s[i]);
    }
    return kem_derive("kyber-kem-reject-v1", secret, ctmat);
}
