cmake_minimum_required(VERSION 3.10)
project(mikrodoh_tests CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Where the source branch is checked out. The default is the parent directory,
# which is what `git worktree add .tests tests` produces.
set(MIKRODOH_SRC "${CMAKE_CURRENT_SOURCE_DIR}/.." CACHE PATH "Checkout of the source branch")

if(NOT EXISTS "${MIKRODOH_SRC}/src/dns.h")
    message(FATAL_ERROR "No mikrodoh source at ${MIKRODOH_SRC}. Pass -DMIKRODOH_SRC=<checkout of main>.")
endif()

set(MIKRODOH_SANITIZE ON CACHE BOOL "Build the tests with ASan and UBSan")

find_package(Threads REQUIRED)

add_executable(mikrodoh_tests
    harness.cpp
    test_cache.cpp
    test_config.cpp
    test_dns.cpp
    test_tcp_conn.cpp

    "${MIKRODOH_SRC}/src/cache.cpp"
    "${MIKRODOH_SRC}/src/config.cpp"
    "${MIKRODOH_SRC}/src/cpu.cpp"
    "${MIKRODOH_SRC}/src/dns.cpp"
    "${MIKRODOH_SRC}/src/tcp_conn.cpp"
)

target_include_directories(mikrodoh_tests PRIVATE "${MIKRODOH_SRC}/src")
target_compile_options(mikrodoh_tests PRIVATE -g -O1 -Wall -Wextra)
target_link_libraries(mikrodoh_tests PRIVATE Threads::Threads)

if(MIKRODOH_SANITIZE)
    target_compile_options(mikrodoh_tests PRIVATE -fsanitize=address,undefined -fno-omit-frame-pointer)
    target_link_options(mikrodoh_tests PRIVATE -fsanitize=address,undefined)
endif()

enable_testing()
add_test(NAME units COMMAND mikrodoh_tests)
