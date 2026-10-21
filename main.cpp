#include <algorithm>
#include <chrono>
#include <filesystem>
#include <iomanip>
#include <iostream>
#include <vector>

#include "encrypt.h"
#include "keyfile.h"

using namespace std;
using clock_type = chrono::steady_clock;

static msg_t block_to_msg(const uint8_t* bytes, size_t n) {
    msg_t m{};
    for (size_t i = 0; i < n; ++i) {
        for (int b = 0; b < 8; ++b) {
            m[8 * i + b] = (bytes[i] >> b) & 1;
        }
    }
    return m;
}

static void msg_to_block(const msg_t& m, uint8_t* bytes) {
    for (size_t i = 0; i < N / 8; ++i) {
        uint8_t v = 0;
        for (int b = 0; b < 8; ++b) {
            v |= static_cast<uint8_t>(m[8 * i + b] << b);
        }
        bytes[i] = v;
    }
}

static vector<msg_t> text_to_blocks(const string& text) {
    vector<uint8_t> plain;
    for (char ch : text) {
        plain.push_back(static_cast<uint8_t>(ch));
    }
    vector<msg_t> blocks;
    for (size_t off = 0; off < plain.size(); off += N / 8) {
        const size_t len = min<size_t>(N / 8, plain.size() - off);
        blocks.push_back(block_to_msg(&plain[off], len));
    }
    return blocks;
}

static string roundtrip_once(const string& text) {
    const seed_t d = gen_seed();
    const seed_t z = gen_seed();
    const secret_key_t s = generate_secret_key(z);
    const public_key_t pk = generate_public_key(d, z, s);

    vector<uint8_t> recovered;
    for (const msg_t& blk : text_to_blocks(text)) {
        const ciphertext_t c = encrypt(pk, blk);
        msg_t m2{};
        if (!decrypt(s, c, m2)) {
            return string();
        }
        uint8_t buf[N / 8];
        msg_to_block(m2, buf);
        recovered.insert(recovered.end(), buf, buf + N / 8);
    }
    while (!recovered.empty() && recovered.back() == 0) {
        recovered.pop_back();
    }
    return string(recovered.begin(), recovered.end());
}

static int run_e2e_test(int rounds, const string& text) {
    cout << "== Тест шифрования-расшифрования ==\n";
    cout << "  сообщение: \"" << text << "\", раундов: " << rounds << "\n";
    int failed = 0;
    for (int r = 0; r < rounds; ++r) {
        const string out = roundtrip_once(text);
        if (out != text) {
            ++failed;
            cout << "  FAIL round " << r << ": \"" << out << "\"\n";
        }
    }
    if (failed == 0) {
        cout << "  OK: " << rounds << "/" << rounds << " round-trip совпало полностью\n\n";
    } else {
        cout << "  FAIL: " << failed << "/" << rounds << " round-trip с ошибкой\n\n";
    }
    return failed;
}

static void run_benchmark(int iters, const string& text) {
    cout << "== Бенчмарк (iters = " << iters << ") ==\n";
    const seed_t d = gen_seed();
    const seed_t z = gen_seed();
    const secret_key_t s = generate_secret_key(z);
    const public_key_t pk = generate_public_key(d, z, s);
    const vector<msg_t> blocks = text_to_blocks(text);

    uint64_t sink = 0;

    const auto enc0 = clock_type::now();
    for (int i = 0; i < iters; ++i) {
        const ciphertext_t c = encrypt(pk, blocks[i % blocks.size()]);
        sink += c.c2[0] + c.c1[0][0];
    }
    const auto enc1 = clock_type::now();

    const ciphertext_t sample = encrypt(pk, blocks[0]);
    const auto dec0 = clock_type::now();
    for (int i = 0; i < iters; ++i) {
        msg_t dm{};
        if (decrypt(s, sample, dm)) {
            sink += dm[0];
        } else {
            sink += 1;
        }
    }
    const auto dec1 = clock_type::now();

    cout << fixed << setprecision(3);
    cout << "  encrypt: " << chrono::duration<double, milli>(enc1 - enc0).count() / iters
         << " ms (в среднем на вызов)\n";
    cout << "  decrypt: " << chrono::duration<double, milli>(dec1 - dec0).count() / iters
         << " ms (в среднем на вызов)\n";
    cout << "  всё сообщение (" << text.size() << " байт, " << blocks.size()
         << " блока): ~" << (chrono::duration<double, milli>(enc1 - enc0).count() / iters +
                            chrono::duration<double, milli>(dec1 - dec0).count() / iters) * blocks.size()
         << " ms (encrypt + decrypt)\n";
    if (sink == 0) {
        cout << "  (unreachable)\n";
    }
}

static bool save_keys_to_disk(const string& text) {
    cout << "\n== Сохранение ключей на диск ==\n";

    const seed_t d = gen_seed();
    const seed_t z = gen_seed();
    const secret_key_t s = generate_secret_key(z);
    const public_key_t pk = generate_public_key(d, z, s);

    const std::filesystem::path dir = std::filesystem::current_path();
    const std::filesystem::path sk_path = dir / "kyber_secret.key";
    const std::filesystem::path pk_path = dir / "kyber_public.key";

    if (!save_secret_key(sk_path.string(), s)) {
        cout << "  FAIL: не удалось записать " << sk_path.string() << "\n";
        return false;
    }
    if (!save_public_key(pk_path.string(), d, pk)) {
        cout << "  FAIL: не удалось записать " << pk_path.string() << "\n";
        return false;
    }
    cout << "  sk -> " << sk_path.string() << " ("
         << std::filesystem::file_size(sk_path) << " байт)\n";
    cout << "  pk -> " << pk_path.string() << " ("
         << std::filesystem::file_size(pk_path) << " байт)\n";

    secret_key_t s2;
    seed_t d2;
    public_key_t pk2;
    const bool sk_ok = load_secret_key(sk_path.string(), s2) && s2 == s;
    const bool pk_ok = load_public_key(pk_path.string(), d2, pk2) && pk2.b == pk.b &&
                       pk2.A == pk.A && d2 == d;
    cout << "  контрольное чтение: " << (sk_ok && pk_ok ? "OK" : "FAIL") << "\n";
    if (!sk_ok || !pk_ok) {
        return false;
    }

    const vector<msg_t> blocks = text_to_blocks(text);
    const bool roundtrip_ok = [&] {
        for (const msg_t& blk : blocks) {
            msg_t dm{};
            if (!decrypt(s2, encrypt(pk2, blk), dm) || dm != blk) {
                return false;
            }
        }
        return true;
    }();
    cout << "  шифрование загруженными ключами (\"" << text << "\"): "
         << (roundtrip_ok ? "OK" : "FAIL") << "\n";
    return roundtrip_ok;
}

int main()
{
    const string text = "Привет, постквантовый мир!";
    const int failed = run_e2e_test(30, text);
    run_benchmark(200, text);
    const bool saved = save_keys_to_disk(text);
    return (failed == 0 && saved) ? 0 : 1;
}
