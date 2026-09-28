cmake_minimum_required(VERSION 3.10)
project(mikrodoh_tests CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Where the source branch is checked out. The default is the parent directory,
# which is what `git worktree add .tests tests` produces.
set(MIKRODOH_SRC "${CMAKE_CURRENT_SOURCE_DIR}/.." CACHE PATH "Checkout of the source branch")

if(NOT EXISTS "${MIKRODOH_SRC}/src/dns/dns.h")
    message(FATAL_ERROR "No mikrodoh source at ${MIKRODOH_SRC}. Pass -DMIKRODOH_SRC=<checkout of main>.")
endif()

set(MIKRODOH_SANITIZE ON CACHE BOOL "Build the tests with ASan and UBSan")

find_package(CURL REQUIRED)
find_package(Threads REQUIRED)

add_executable(mikrodoh_tests
    harness.cpp
    test_cache.cpp
    test_coalesce.cpp
    test_config.cpp
    test_dispatch.cpp
    test_dns.cpp
    test_health.cpp
    test_net.cpp
    test_ratelimit.cpp
    test_sandbox.cpp
    test_tcp_conn.cpp
    test_upstream.cpp

    "${MIKRODOH_SRC}/src/dns/cache.cpp"
    "${MIKRODOH_SRC}/src/dns/coalesce.cpp"
    "${MIKRODOH_SRC}/src/core/config.cpp"
    "${MIKRODOH_SRC}/src/core/cpu.cpp"
    "${MIKRODOH_SRC}/src/upstream/dispatch.cpp"
    "${MIKRODOH_SRC}/src/dns/dns.cpp"
    "${MIKRODOH_SRC}/src/dns/health.cpp"
    "${MIKRODOH_SRC}/src/net/net.cpp"
    "${MIKRODOH_SRC}/src/net/ratelimit.cpp"
    "${MIKRODOH_SRC}/src/core/sandbox.cpp"
    "${MIKRODOH_SRC}/src/net/tcp_conn.cpp"
    "${MIKRODOH_SRC}/src/upstream/transfer.cpp"
    "${MIKRODOH_SRC}/src/upstream/upstream.cpp"
)

target_include_directories(mikrodoh_tests PRIVATE "${MIKRODOH_SRC}/src")
target_compile_options(mikrodoh_tests PRIVATE -g -O1 -Wall -Wextra)
target_link_libraries(mikrodoh_tests PRIVATE CURL::libcurl Threads::Threads)

if(MIKRODOH_SANITIZE)
    target_compile_options(mikrodoh_tests PRIVATE -fsanitize=address,undefined -fno-omit-frame-pointer)
    target_link_options(mikrodoh_tests PRIVATE -fsanitize=address,undefined)
endif()

# libFuzzer target for the wire parser. Needs clang.
option(MIKRODOH_FUZZ "Build the fuzz_dns target" OFF)
if(MIKRODOH_FUZZ)
    add_executable(fuzz_dns
        fuzz/fuzz_dns.cpp
        "${MIKRODOH_SRC}/src/dns/cache.cpp"
        "${MIKRODOH_SRC}/src/dns/dns.cpp"
        "${MIKRODOH_SRC}/src/dns/health.cpp"
        "${MIKRODOH_SRC}/src/net/net.cpp"
    )
    target_include_directories(fuzz_dns PRIVATE "${MIKRODOH_SRC}/src")
    target_compile_options(fuzz_dns PRIVATE -g -O1 -fsanitize=fuzzer,address,undefined
                                            -fno-sanitize-recover=undefined)
    target_link_options(fuzz_dns PRIVATE -fsanitize=fuzzer,address,undefined)
endif()

enable_testing()
add_test(NAME units COMMAND mikrodoh_tests)
