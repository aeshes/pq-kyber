#include <fstream>
#include <iomanip>
#include <iostream>
#include <vector>

#include "encrypt.h"
#include "keyfile.h"

using namespace std;

static msg_t to_msg(const string& text) {
    msg_t m{};
    const size_t n = text.size() < N / 8 ? text.size() : N / 8;
    for (size_t i = 0; i < n; ++i) {
        const uint8_t byte = static_cast<uint8_t>(text[i]);
        for (int b = 0; b < 8; ++b) {
            m[8 * i + b] = (byte >> b) & 1;
        }
    }
    return m;
}

static string to_text(const msg_t& m) {
    string out;
    for (size_t i = 0; i < N / 8; ++i) {
        uint8_t byte = 0;
        for (int b = 0; b < 8; ++b) {
            byte |= static_cast<uint8_t>(m[8 * i + b] << b);
        }
        if (byte == 0) {
            break;
        }
        out.push_back(static_cast<char>(byte));
    }
    return out;
}

int main()
{
    cout << "======== 0. Жертва: выпуск ключей и шифрование секрета ========\n";
    const string secret = "S3cr3t: vstrecha v Sankt-P";

    const seed_t d = gen_seed();
    const seed_t z = gen_seed();
    const secret_key_t s = generate_secret_key(z);
    const public_key_t pk = generate_public_key(d, z, s);

    save_secret_key("kyber_secret.key", s);
    save_public_key("kyber_public.key", d, pk);

    const msg_t m = to_msg(secret);
    const ciphertext_t ct = encrypt(pk, m);
    cout << "  секрет жертвы: \"" << secret << "\"\n";
    cout << "  z (сид секрета) хранится только у жертвы и НЕ попадает в pk\n";
    msg_t own{};
    cout << "  свои же ключи: decrypt(sk, ct) = \""
         << (decrypt(s, ct, own) ? to_text(own) : "<ОТКАЗ>") << "\"\n";

    cout << "\n======== 1. АТАКА: попытка восстановить sk из pk (старый метод) ========\n";
    ifstream f("kyber_public.key", std::ios::binary);
    const vector<uint8_t> blob((std::istreambuf_iterator<char>(f)),
                               std::istreambuf_iterator<char>());
    if (blob.size() < 5 + SEED_BYTES) {
        cerr << "плохой файл pk\n";
        return 1;
    }
    seed_t d_attack;
    for (int i = 0; i < SEED_BYTES; ++i) {
        d_attack[i] = blob[5 + i];
    }
    cout << "  атакующий извлёк d из pk (байты 5..36): " << hex << setfill('0');
    for (uint8_t b : d_attack) {
        cout << setw(2) << (int)b;
    }
    cout << dec << "\n";

    const secret_key_t s_attack = generate_secret(d_attack);
    const matrix_t A_attack = gen_matrix(d_attack);
    const polyvec_t e_attack = generate_error(d_attack);

    seed_t d_loaded;
    public_key_t pk_loaded;
    if (!load_public_key("kyber_public.key", d_loaded, pk_loaded)) {
        cerr << "не удалось загрузить pk\n";
        return 1;
    }

    const bool pk_matches = (add(mult(s_attack, A_attack), e_attack) == pk_loaded.b);
    cout << "  проверка b == generate_secret(d)·A + generate_error(d): "
         << (pk_matches ? "СОВПАДАЕТ (система всё ещё сломана!)"
                        : "НЕ СОВПАДАЕТ -> это не настоящий секрет")
         << "\n";

    msg_t m_attack{};
    const bool attack_dec_ok = decrypt(s_attack, ct, m_attack);
    cout << "  decrypt(подозренным sk, перехваченный ct) = ";
    if (attack_dec_ok) {
        cout << "\"" << to_text(m_attack) << "\" (ожидаемое: \"" << secret << "\")\n";
    } else {
        cout << "ОТКАЗ (проверка тега не пройдена)\n";
    }

    cout << "\n======== 2. АТАКА: подмена шифротекста (malleability) ========\n";
    ciphertext_t tampered = ct;
    const int bit = 7;
    const int half_q = (Q + 1) / 2;
    int v = tampered.c2[bit] + half_q;
    if (v >= Q) {
        v -= Q;
    }
    tampered.c2[bit] = v;

    msg_t tampered_dec{};
    const bool tamper_ok = decrypt(s, tampered, tampered_dec);
    cout << "  к c2[" << bit << "] добавлено round(q/2) = " << half_q << " (mod q)\n";
    if (tamper_ok) {
        int diff_count = 0;
        for (int i = 0; i < N; ++i) {
            if (m[i] != tampered_dec[i]) {
                ++diff_count;
            }
        }
        cout << "  подмена ПРОШЛА: расшифровано сообщение отличается на " << diff_count
             << " бит(ах) -> целостность не обеспечена\n";
    } else {
        cout << "  подмена ОТВЕРГНУТА: тег целостности не совпал, дешифрование вернуло отказ\n";
    }

    cout << "\n======== ИТОГ ========\n";
    const bool cca_defended = !tamper_ok;
    if (!pk_matches && (!attack_dec_ok || m_attack != m) && cca_defended) {
        cout << "  АТАКА 1 ОТБИТА: sk не выводится из открытого d (нужен секретный z).\n";
        cout << "  АТАКА 2 ОТБИТА: тег целостности (вариант 1) блокирует подмену шифротекста.\n";
        return 0;
    }
    if (!pk_matches && (!attack_dec_ok || m_attack != m)) {
        cout << "  АТАКА 1 ОТБИТА, но система всё ещё malleable (тег не проверен)\n";
        return 0;
    }
    cout << "  ВНИМАНИЕ: система по-прежнему компрометируется описанным способом\n";
    return 1;
}
