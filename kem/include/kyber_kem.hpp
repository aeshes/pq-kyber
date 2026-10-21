// =============================================================================
// kyber_kem.hpp — автономная header-only реализация KEM на Module-LWE.
//
// Конструкция наследует схему учебного проекта kyber (q = 7681, n = 256,
// k = 2, η = 2) и повторяет её протокол целиком:
//
//   генерация ключей:
//       A  ← равномерная матрица k×k из открытого сида d   (только ρ!)
//       s,e← распределение χ (centered binomial) из СЕКРЕТНОГО сида z
//       pk = (d, b = sA + e),  sk = s
//
//   инкапсуляция:
//       m  ← случайные 256 бит;  r, e1, e2 ← χ (свежие монеты)
//       c1 = rAᵀ + e1
//       c2 = r·b + e2 + m·round(q/2)
//       tag = SHA3(integrity-domain ‖ m ‖ c1 ‖ c2)       — проверка целостности
//       K   = SHA3(key-domain       ‖ m ‖ c1 ‖ c2)       — общий секрет
//
//   деинкапсуляция:
//       m' = decode(c2 − s·c1);  если tag(m',c1,c2) сходится → K (тот же KDF),
//       иначе — неявный отказ: K_rej = SHA3(reject-domain ‖ sk ‖ c1 ‖ c2).
//
//   Это Fujisaki–Okamoto-подобная трансформация: тег связывает сообщение с
//   шифротекстом (роверификации перешифрования), а отказ неотличим от
//   случайного ключа, потому что зависит от секретного sk.
//
// Схема Учебная: NTT на табличных константах, mt19937_64 как PRNG и
// отсутствие константного времени — не являются признаками боевого KEM.
// =============================================================================

#ifndef KYBER_KEM_HPP
#define KYBER_KEM_HPP

#include <array>
#include <cstdint>
#include <cstring>
#include <random>
#include <vector>

namespace kyber_kem {

// --------------------------- параметры схемы ---------------------------------

inline constexpr int N = 256;          // число коэффициентов полинома
inline constexpr int K = 2;            // размерность модуля (число полиномов в векторе)
inline constexpr int Q = 7681;         // модуль кольца Z_q[X]/(X^N + 1)
inline constexpr int ROOT = 198;       // примитивный корень 256-й степени из 1 по модулю Q
inline constexpr int ETA = 2;          // параметр centered binomial распределения χ
inline constexpr int SEED_BYTES = 32;  // 256-битный сид

// ------------------------------ публичные типы -------------------------------

using Seed = std::array<uint8_t, SEED_BYTES>;
using SharedKey = Seed;
using Tag = Seed;

using Poly = std::array<int32_t, N>;        // элемент R_q
using PolyVec = std::array<Poly, K>;        // элемент R_q^k (строка)
using Matrix = std::array<PolyVec, K>;      // матрица k×k над R_q

struct PublicKey {
    Seed d;        // открытый сид; матрица A восстанавливается из него
    PolyVec b;     // b = sA + e
};

struct SecretKey {
    PolyVec s;     // секрет модуля
};

struct KeyPair {
    PublicKey pk;
    SecretKey sk;
};

struct Ciphertext {
    PolyVec c1;
    Poly c2;
    Tag tag;
};

struct KemResult {
    Ciphertext ct;
    SharedKey key;
};

// ------------------------------ публичный API --------------------------------

// Свежая пара ключей; энтропия берётся из ОС (random_device).
inline KeyPair generate_keypair();

// Инкапсуляция: возвращает шифротекст и общий ключ (оба известны отправителю).
inline KemResult encapsulate(const PublicKey& pk);

// Деинкапсуляция: настоящий ключ для корректного шифротекста, иначе —
// псевдослучайный ключ неявного отказа (неотличимый для атакующего).
inline SharedKey decapsulate(const SecretKey& sk, const Ciphertext& ct);

// Быстрая самопроверка библиотеки (векторы SHA3 + round-trip KEM + отказ).
inline bool self_test();

// ================================ детали ====================================

namespace detail {

// ---------------------------- вспомогательное --------------------------------

inline int32_t mod_q(int64_t x) {
    x %= Q;
    if (x < 0) {
        x += Q;
    }
    return static_cast<int32_t>(x);
}

// 7-битный реверс — порядок zeta-множителей в NTT (bit-reversed table).
constexpr int brv7(int x) {
    int y = 0;
    for (int i = 0; i < 7; ++i) {
        y = (y << 1) | (x & 1);
        x >>= 1;
    }
    return y;
}

// zetas[i] = ROOT^brv7(i) mod Q — множители бабочек прямого NTT.
inline constexpr std::array<int32_t, 128> ZETAS = [] {
    std::array<int32_t, 128> z{};
    for (int i = 0; i < 128; ++i) {
        int e = brv7(i);
        int64_t base = ROOT;
        int64_t r = 1;
        while (e > 0) {
            if (e & 1) {
                r = r * base % Q;
            }
            base = base * base % Q;
            e >>= 1;
        }
        z[i] = static_cast<int32_t>(r);
    }
    return z;
}();

// ---------------------- умножение в кольце R_q (NTT) ------------------------

inline Poly ntt_forward(const Poly& in) {
    Poly a = in;
    int k = 1;
    for (int len = 128; len >= 2; len >>= 1) {
        for (int start = 0; start < N; start += 2 * len) {
            const int32_t zeta = ZETAS[k++];
            for (int j = start; j < start + len; ++j) {
                const int32_t t = zeta * a[j + len] % Q;
                a[j + len] = mod_q(a[j] - t);
                a[j] = mod_q(a[j] + t);
            }
        }
    }
    return a;
}

// Обратное преобразование; бабочки домножаются на ζ (не на ζ⁻¹), поэтому
// итоговая нормализовка — 1/128 (7621), а не 1/256.
inline Poly ntt_inverse(const Poly& in) {
    Poly a = in;
    int k = 127;
    for (int len = 2; len <= 128; len <<= 1) {
        for (int start = 0; start < N; start += 2 * len) {
            const int32_t zeta = ZETAS[k--];
            for (int j = start; j < start + len; ++j) {
                const int32_t t = a[j];
                a[j] = mod_q(t + a[j + len]);
                a[j + len] = static_cast<int32_t>(mod_q(a[j + len] - t) * zeta % Q);
            }
        }
    }
    for (int i = 0; i < N; ++i) {
        a[i] = static_cast<int32_t>(a[i] * 7621LL % Q);
    }
    return a;
}

// Покомпонентное перемножение в NTT-области (спаренные коэффициенты).
inline Poly pointwise_mul(const Poly& a, const Poly& b) {
    Poly out{};
    for (int j = 0; j < 128; ++j) {
        int32_t zeta = ZETAS[64 + j / 2];
        if (j & 1) {
            zeta = Q - zeta;
        }
        const int64_t a0 = a[2 * j], a1 = a[2 * j + 1];
        const int64_t b0 = b[2 * j], b1 = b[2 * j + 1];
        out[2 * j] = static_cast<int32_t>((a0 * b0 + a1 * b1 % Q * zeta) % Q);
        out[2 * j + 1] = static_cast<int32_t>((a0 * b1 + a1 * b0) % Q);
    }
    return out;
}

inline Poly poly_mul(const Poly& f, const Poly& g) {
    return ntt_inverse(pointwise_mul(ntt_forward(f), ntt_forward(g)));
}

// ------------------------- векторно-матричные слои ---------------------------

inline PolyVec polyvec_add(const PolyVec& a, const PolyVec& b) {
    PolyVec r{};
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

// vA: r[j] = Σᵢ v[i]·A[i][j]
inline PolyVec polyvec_mul(const PolyVec& v, const Matrix& A) {
    PolyVec r{};
    for (int j = 0; j < K; ++j) {
        for (int i = 0; i < K; ++i) {
            const Poly t = poly_mul(v[i], A[i][j]);
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

// vAᵀ: r[j] = Σᵢ v[i]·A[j][i]
inline PolyVec polyvec_mul_transpose(const PolyVec& v, const Matrix& A) {
    PolyVec r{};
    for (int j = 0; j < K; ++j) {
        for (int i = 0; i < K; ++i) {
            const Poly t = poly_mul(v[i], A[j][i]);
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

// Скалярное произведение векторов над R_q: Σᵢ a[i]·b[i].
inline Poly polyvec_dot(const PolyVec& a, const PolyVec& b) {
    Poly r{};
    for (int i = 0; i < K; ++i) {
        const Poly t = poly_mul(a[i], b[i]);
        for (int c = 0; c < N; ++c) {
            r[c] += t[c];
            if (r[c] >= Q) {
                r[c] -= Q;
            }
        }
    }
    return r;
}

// --------------------------------- SHA3-256 ----------------------------------

inline uint64_t rotl64(uint64_t v, int n) {
    n &= 63;
    return n == 0 ? v : (v << n) | (v >> (64 - n));
}

inline constexpr uint64_t RC[24] = {
    0x0000000000000001ULL, 0x0000000000008082ULL, 0x800000000000808aULL,
    0x8000000080008000ULL, 0x000000000000808bULL, 0x0000000080000001ULL,
    0x8000000080008081ULL, 0x8000000000008009ULL, 0x000000000000008aULL,
    0x0000000000000088ULL, 0x0000000080008009ULL, 0x000000008000000aULL,
    0x000000008000808bULL, 0x800000000000008bULL, 0x8000000000008089ULL,
    0x8000000000008003ULL, 0x8000000000008002ULL, 0x8000000000000080ULL,
    0x000000000000800aULL, 0x800000008000000aULL, 0x8000000080008081ULL,
    0x8000000000008080ULL, 0x0000000080000001ULL, 0x8000000080008008ULL};

inline constexpr int RHO[5][5] = {
    {0, 36, 3, 41, 18},
    {1, 44, 10, 45, 2},
    {62, 6, 43, 15, 61},
    {28, 55, 25, 21, 56},
    {27, 20, 39, 8, 14},
};

inline void keccak_f1600(uint64_t A[25]) {
    for (int t = 0; t < 24; ++t) {
        uint64_t C[5];
        for (int x = 0; x < 5; ++x) {
            C[x] = A[x] ^ A[x + 5] ^ A[x + 10] ^ A[x + 15] ^ A[x + 20];
        }
        for (int x = 0; x < 5; ++x) {
            const uint64_t d = C[(x + 4) % 5] ^ rotl64(C[(x + 1) % 5], 1);
            for (int y = 0; y < 5; ++y) {
                A[x + 5 * y] ^= d;
            }
        }
        uint64_t B[25];
        for (int x = 0; x < 5; ++x) {
            for (int y = 0; y < 5; ++y) {
                const int sx = (x + 3 * y) % 5;
                B[x + 5 * y] = rotl64(A[sx + 5 * x], RHO[sx][x]);
            }
        }
        for (int y = 0; y < 5; ++y) {
            uint64_t b[5];
            for (int x = 0; x < 5; ++x) {
                b[x] = B[x + 5 * y];
            }
            for (int x = 0; x < 5; ++x) {
                A[x + 5 * y] = b[x] ^ ((~b[(x + 1) % 5]) & b[(x + 2) % 5]);
            }
        }
        A[0] ^= RC[t];
    }
}

inline Tag sha3_256(const std::vector<uint8_t>& data) {
    constexpr std::size_t RATE = 136;
    uint64_t A[25] = {0};
    std::size_t i = 0;
    while (data.size() - i >= RATE) {
        for (std::size_t j = 0; j < RATE; ++j) {
            A[j / 8] ^= static_cast<uint64_t>(data[i + j]) << (8 * (j % 8));
        }
        keccak_f1600(A);
        i += RATE;
    }
    const std::size_t L = data.size() - i;
    for (std::size_t j = 0; j < L; ++j) {
        A[j / 8] ^= static_cast<uint64_t>(data[i + j]) << (8 * (j % 8));
    }
    A[L / 8] ^= 0x06ULL << (8 * (L % 8));       // домен SHA3 (не исходного Keccak)
    A[(RATE - 1) / 8] ^= 0x80ULL << (8 * ((RATE - 1) % 8));
    keccak_f1600(A);
    Tag out{};
    for (std::size_t j = 0; j < out.size(); ++j) {
        out[j] = static_cast<uint8_t>(A[j / 8] >> (8 * (j % 8)));
    }
    return out;
}

// ---------------------------- PRNG и дискретизация ----------------------------

inline Seed random_seed() {
    std::random_device rd;
    Seed s{};
    for (std::size_t i = 0; i < s.size(); i += 4) {
        const uint32_t v = rd();
        s[i] = static_cast<uint8_t>(v);
        s[i + 1] = static_cast<uint8_t>(v >> 8);
        s[i + 2] = static_cast<uint8_t>(v >> 16);
        s[i + 3] = static_cast<uint8_t>(v >> 24);
    }
    return s;
}

// Доменные теги: один и тот же сид даёт независимые потоки для A, s, e, шифрования.
constexpr uint8_t TAG_MATRIX = 0;
constexpr uint8_t TAG_SECRET = 1;
constexpr uint8_t TAG_ERROR = 2;
constexpr uint8_t TAG_ENCRYPT = 3;

inline std::mt19937_64 make_rng(const Seed& seed, uint8_t tag) {
    std::vector<uint32_t> words;
    words.reserve(seed.size() / 4 + 1);
    words.push_back(tag);
    for (std::size_t i = 0; i + 4 <= seed.size(); i += 4) {
        words.push_back(static_cast<uint32_t>(seed[i]) |
                        (static_cast<uint32_t>(seed[i + 1]) << 8) |
                        (static_cast<uint32_t>(seed[i + 2]) << 16) |
                        (static_cast<uint32_t>(seed[i + 3]) << 24));
    }
    std::seed_seq seq(words.begin(), words.end());
    return std::mt19937_64(seq);
}

// Полином из centered binomial распределения χ_η:
// каждый коэффициент = (#единиц в первых η битах) − (#единиц во вторых η битах).
inline Poly sample_chi(std::mt19937_64& gen) {
    std::uniform_int_distribution<int> bit(0, 1);
    Poly f{};
    for (int i = 0; i < N; ++i) {
        int a = 0, b = 0;
        for (int j = 0; j < ETA; ++j) {
            a += bit(gen);
        }
        for (int j = 0; j < ETA; ++j) {
            b += bit(gen);
        }
        f[i] = mod_q(a - b);
    }
    return f;
}

// Полином с равномерными коэффициентами из [0, Q) — материал для матрицы A.
inline Poly sample_uniform(std::mt19937_64& gen) {
    std::uniform_int_distribution<int32_t> dist(0, Q - 1);
    Poly f{};
    for (int i = 0; i < N; ++i) {
        f[i] = dist(gen);
    }
    return f;
}

inline PolyVec sample_chi_vec(std::mt19937_64& gen) {
    PolyVec v{};
    for (int i = 0; i < K; ++i) {
        v[i] = sample_chi(gen);
    }
    return v;
}

// Равномерная матрица A из открытого сида d (публично воспроизводима).
inline Matrix gen_matrix(const Seed& d) {
    auto gen = make_rng(d, TAG_MATRIX);
    Matrix A{};
    for (int i = 0; i < K; ++i) {
        for (int j = 0; j < K; ++j) {
            A[i][j] = sample_uniform(gen);
        }
    }
    return A;
}

// ------------------------- CPA-PKE с тегом целостности -----------------------

using MsgBits = std::array<uint8_t, N>;  // 256 бит, по одному на коэффициент

// бит → коэффициент: 0 или round(q/2) = ⌈q/2⌉ (как poly_decompress в Kyber)
inline Poly encode_message(const MsgBits& m) {
    Poly p{};
    for (int i = 0; i < N; ++i) {
        p[i] = static_cast<int32_t>((m[i] & 1) * ((Q + 1) / 2));
    }
    return p;
}

// коэффициент → бит по ближайшему из {0, round(q/2)} по модулю q
inline MsgBits decode_message(const Poly& p) {
    MsgBits m{};
    for (int i = 0; i < N; ++i) {
        int32_t x = p[i];
        if (x > (Q + 1) / 2) {
            x -= Q;  // центрирование: x ∈ [-q/2, q/2]
        }
        m[i] = ((x < 0 ? -x : x) > Q / 4) ? 1 : 0;
    }
    return m;
}

inline void push_u16(std::vector<uint8_t>& v, int32_t x) {
    v.push_back(static_cast<uint8_t>(x & 0xFF));
    v.push_back(static_cast<uint8_t>((x >> 8) & 0xFF));
}

inline void push_poly(std::vector<uint8_t>& v, const Poly& p) {
    for (int c = 0; c < N; ++c) {
        push_u16(v, p[c]);
    }
}

inline void push_polyvec(std::vector<uint8_t>& v, const PolyVec& pv) {
    for (int i = 0; i < K; ++i) {
        push_poly(v, pv[i]);
    }
}

inline std::array<uint8_t, 32> pack_msg(const MsgBits& m) {
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

// Тег целостности связывает сообщение с шифротекстом и играет роль
// проверки перешифрования в FO: без знания m подделить тег не выходит.
inline Tag compute_tag(const MsgBits& m, const PolyVec& c1, const Poly& c2) {
    static const char LABEL[] = "kyber-kem-integrity-v1";
    std::vector<uint8_t> buf;
    buf.insert(buf.end(), LABEL, LABEL + sizeof(LABEL) - 1);
    const auto packed = pack_msg(m);
    buf.insert(buf.end(), packed.begin(), packed.end());
    push_polyvec(buf, c1);
    push_poly(buf, c2);
    return sha3_256(buf);
}

inline bool tag_equal(const Tag& a, const Tag& b) {
    uint8_t acc = 0;
    for (std::size_t i = 0; i < a.size(); ++i) {
        acc |= static_cast<uint8_t>(a[i] ^ b[i]);
    }
    return acc == 0;
}

inline Ciphertext cpa_encrypt(const PublicKey& pk, const MsgBits& m, std::mt19937_64& gen) {
    const Matrix A = gen_matrix(pk.d);
    const PolyVec r = sample_chi_vec(gen);
    const PolyVec e1 = sample_chi_vec(gen);
    const Poly e2 = sample_chi(gen);

    Ciphertext c;
    c.c1 = polyvec_add(polyvec_mul_transpose(r, A), e1);
    const Poly rb = polyvec_dot(r, pk.b);
    const Poly msg = encode_message(m);
    for (int i = 0; i < N; ++i) {
        c.c2[i] = mod_q(static_cast<int64_t>(rb[i]) + e2[i] + msg[i]);
    }
    c.tag = compute_tag(m, c.c1, c.c2);
    return c;
}

inline bool cpa_decrypt(const SecretKey& sk, const Ciphertext& c, MsgBits& m) {
    const Poly cs = polyvec_dot(c.c1, sk.s);
    Poly u{};
    for (int i = 0; i < N; ++i) {
        int32_t v = c.c2[i] - cs[i];
        if (v < 0) {
            v += Q;
        }
        u[i] = v;
    }
    const MsgBits candidate = decode_message(u);
    if (!tag_equal(c.tag, compute_tag(candidate, c.c1, c.c2))) {
        m = MsgBits{};
        return false;
    }
    m = candidate;
    return true;
}

// ----------------------------- KEM-слой (KDF) --------------------------------

inline SharedKey kem_kdf(const char* domain, const std::vector<uint8_t>& secret,
                         const PolyVec& c1, const Poly& c2) {
    std::vector<uint8_t> buf;
    buf.insert(buf.end(), domain, domain + std::strlen(domain));
    buf.insert(buf.end(), secret.begin(), secret.end());
    push_polyvec(buf, c1);
    push_poly(buf, c2);
    return sha3_256(buf);
}

inline std::vector<uint8_t> secret_key_bytes(const SecretKey& sk) {
    std::vector<uint8_t> v;
    push_polyvec(v, sk.s);
    return v;
}

}  // namespace detail

// ============================ публичные функции ===============================

inline KeyPair generate_keypair() {
    const Seed d = detail::random_seed();  // открытый сид матрицы
    const Seed z = detail::random_seed();  // секретный сид шума

    auto gen_s = detail::make_rng(z, detail::TAG_SECRET);
    auto gen_e = detail::make_rng(z, detail::TAG_ERROR);

    KeyPair kp;
    kp.sk.s = detail::sample_chi_vec(gen_s);
    const PolyVec e = detail::sample_chi_vec(gen_e);

    kp.pk.d = d;
    const Matrix A = detail::gen_matrix(d);
    kp.pk.b = detail::polyvec_add(detail::polyvec_mul(kp.sk.s, A), e);
    return kp;
}

inline KemResult encapsulate(const PublicKey& pk) {
    const Seed coins = detail::random_seed();
    auto gen = detail::make_rng(coins, detail::TAG_ENCRYPT);

    std::uniform_int_distribution<uint64_t> dist;
    detail::MsgBits m{};
    for (int w = 0; w < N / 64; ++w) {
        const uint64_t x = dist(gen);
        for (int b = 0; b < 64; ++b) {
            m[64 * w + b] = static_cast<uint8_t>((x >> b) & 1);
        }
    }

    KemResult out;
    out.ct = detail::cpa_encrypt(pk, m, gen);
    const auto packed = detail::pack_msg(m);
    out.key = detail::kem_kdf("kyber-kem-key-v1",
                              std::vector<uint8_t>(packed.begin(), packed.end()),
                              out.ct.c1, out.ct.c2);
    return out;
}

inline SharedKey decapsulate(const SecretKey& sk, const Ciphertext& ct) {
    detail::MsgBits m{};
    if (detail::cpa_decrypt(sk, ct, m)) {
        const auto packed = detail::pack_msg(m);
        return detail::kem_kdf("kyber-kem-key-v1",
                               std::vector<uint8_t>(packed.begin(), packed.end()),
                               ct.c1, ct.c2);
    }
    // Неявный отказ: ключ неотличим от настоящего, а его вычисление требует sk.
    return detail::kem_kdf("kyber-kem-reject-v1", detail::secret_key_bytes(sk),
                           ct.c1, ct.c2);
}

inline bool self_test() {
    bool ok = true;

    // эталонные векторы SHA3-256
    const std::vector<uint8_t> empty;
    Tag h = detail::sha3_256(empty);
    ok = ok && h[0] == 0xa7 && h[1] == 0xff && h[2] == 0xc6 && h[31] == 0x4a;
    std::vector<uint8_t> abc = {'a', 'b', 'c'};
    h = detail::sha3_256(abc);
    ok = ok && h[0] == 0x3a && h[1] == 0x98 && h[2] == 0x5d && h[31] == 0x32;

    // KEM: инкапсуляция/деинкапсуляция согласуют ключ, отказ детерминирован
    for (int t = 0; t < 5 && ok; ++t) {
        const KeyPair kp = generate_keypair();
        const KemResult e = encapsulate(kp.pk);
        ok = ok && (decapsulate(kp.sk, e.ct) == e.key);

        Ciphertext tampered = e.ct;
        int32_t v = tampered.c2[0] + (Q + 1) / 2;
        if (v >= Q) {
            v -= Q;
        }
        tampered.c2[0] = v;
        const SharedKey rej = decapsulate(kp.sk, tampered);
        ok = ok && (rej != e.key) && (rej == decapsulate(kp.sk, tampered));
    }
    return ok;
}

}  // namespace kyber_kem

#endif  // KYBER_KEM_HPP
