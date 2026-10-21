// =============================================================================
// Демонстрация работы библиотеки kyber_kem (Module-LWE KEM).
//
// Показывает полный цикл: самопроверка -> генерация ключей -> инкапсуляция
// (отправитель) -> деинкапсуляция (получатель) -> сверка общих секретов, а
// также замеры времени на инкапсуляцию и деинкапсуляцию.
// =============================================================================

#include <chrono>
#include <iomanip>
#include <iostream>

#include <kyber_kem.hpp>

namespace {

using clock_type = std::chrono::steady_clock;

// Замер усреднённого времени вызова f, повторяемого iters раз. Результат в мс.
template <class F>
double bench(int iters, F&& f) {
    const auto t0 = clock_type::now();
    volatile uint8_t sink = 0;
    for (int i = 0; i < iters; ++i) {
        sink ^= f();
    }
    const auto t1 = clock_type::now();
    (void)sink;
    return std::chrono::duration<double, std::milli>(t1 - t0).count() / iters;
}

}  // namespace

int main()
{
    using namespace kyber_kem;
    std::cout << std::fixed << std::setprecision(3);

    std::cout << "== kyber_kem demo ==\n";
    std::cout << "  параметры: N=" << N << ", K=" << K << ", Q=" << Q
              << ", ETA=" << ETA << "\n";

    if (!self_test()) {
        std::cerr << "  self_test: FAIL\n";
        return 1;
    }
    std::cout << "  self_test: OK\n";

    const KeyPair kp = generate_keypair();

    int agree = 0;
    const int rounds = 50;
    for (int i = 0; i < rounds; ++i) {
        const KemResult e = encapsulate(kp.pk);
        const SharedKey k = decapsulate(kp.sk, e.ct);
        agree += (k == e.key);
    }
    std::cout << "  согласование ключей: " << agree << "/" << rounds << "\n";

    if (agree != rounds) {
        std::cerr << "  FAIL: ключи не сошлись\n";
        return 1;
    }

    // Замер инкапсуляции (ключ возвращаем как число, чтобы предотвратить
    // оптимизацию цикла).
    double enc_ms = bench(300, [&]() -> uint8_t {
        const KemResult e = encapsulate(kp.pk);
        return e.key[0];
    });

    // Деинкапсуляция требует шифротекста: заготовим один.
    const Ciphertext ct = encapsulate(kp.pk).ct;
    double dec_ms = bench(300, [&]() -> uint8_t {
        const SharedKey k = decapsulate(kp.sk, ct);
        return k[0];
    });

    std::cout << "  encapsulate: " << enc_ms << " ms\n";
    std::cout << "  decapsulate: " << dec_ms << " ms\n";

    // Демонстрация неявного отказа: подделка даёт другой, но детерминированный ключ.
    Ciphertext tampered = ct;
    tampered.c2[0] = (tampered.c2[0] + (Q + 1) / 2) % Q;
    const SharedKey rejected = decapsulate(kp.sk, tampered);
    const bool rejection_ok = rejected != decapsulate(kp.sk, ct) &&
                              rejected == decapsulate(kp.sk, tampered);
    std::cout << "  неявный отказ на подделке: "
              << (rejection_ok ? "да (детерминированный псевдослучайный ключ)" : "нет") << "\n";

    return rejection_ok ? 0 : 1;
}
