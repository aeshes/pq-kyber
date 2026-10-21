cmake_minimum_required(VERSION 3.16)

project(kyber LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_subdirectory(kem)

add_executable(kyber main.cpp
    ntt.h
    ntt.cpp
    params.h
    hash.h
    hash.cpp
    encrypt.h
    encrypt.cpp
    keys.h
    keys.cpp
    keyfile.h
    keyfile.cpp
    polyvec.h
    polyvec.cpp
    rand.h
    rand.cpp)

include(CTest)
find_package(GTest REQUIRED)

add_executable(tests
    tests/ntt_test.cpp
    tests/encrypt_test.cpp
    tests/hash_test.cpp
    tests/keyfile_test.cpp
    hash.h
    hash.cpp
    encrypt.h
    encrypt.cpp
    keys.h
    keys.cpp
    keyfile.h
    keyfile.cpp
    polyvec.h
    polyvec.cpp
    rand.h
    rand.cpp
    ntt.h
    ntt.cpp
    params.h)
target_link_libraries(tests PRIVATE GTest::gtest_main)
target_include_directories(tests PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})

include(GoogleTest)
gtest_discover_tests(tests)

add_executable(attack attack.cpp
    hash.h
    hash.cpp
    ntt.h
    ntt.cpp
    params.h
    encrypt.h
    encrypt.cpp
    keys.h
    keys.cpp
    keyfile.h
    keyfile.cpp
    polyvec.h
    polyvec.cpp
    rand.h
    rand.cpp)
