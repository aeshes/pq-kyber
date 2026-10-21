# =============================================================================
# kyber_kem — автономная header-only библиотека KEM на Module-LWE.
#
# Не зависит от остальных целей проекта и не требует компиляции: достаточно
#     target_link_libraries(<цель> PRIVATE kyber::kem)
# и в коде
#     #include <kyber_kem.hpp>
# =============================================================================

add_library(kyber_kem INTERFACE)
add_library(kyber::kem ALIAS kyber_kem)

target_include_directories(kyber_kem INTERFACE
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:include>
)

target_compile_features(kyber_kem INTERFACE cxx_std_17)

# ---------------------------------------------------------------------------
# Демонстрационный пример использования библиотеки.
# ---------------------------------------------------------------------------
add_executable(kyber_kem_demo examples/demo.cpp)
target_link_libraries(kyber_kem_demo PRIVATE kyber::kem)
