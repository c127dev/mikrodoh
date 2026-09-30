cmake_minimum_required(VERSION 3.10)
project(mikrodoh CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release)
endif()

# Per-board compiler tuning, e.g. -mcpu=cortex-a15. See boards/*.conf.
set(MIKRODOH_TUNE "" CACHE STRING "Extra compiler flags for the target board")
separate_arguments(MIKRODOH_TUNE_ARGS NATIVE_COMMAND "${MIKRODOH_TUNE}")

option(MIKRODOH_SMALL "Optimise for size: -Os, LTO, section GC, stripped" OFF)

find_package(CURL REQUIRED)
find_package(Threads REQUIRED)

add_executable(mikrodoh
    src/main.cpp
    src/core/config.cpp
    src/core/cpu.cpp
    src/core/privs.cpp
    src/core/sandbox.cpp
    src/core/stats.cpp
    src/dns/cache.cpp
    src/dns/coalesce.cpp
    src/dns/dns.cpp
    src/dns/health.cpp
    src/net/net.cpp
    src/net/ratelimit.cpp
    src/net/tcp_conn.cpp
    src/net/tcp_server.cpp
    src/net/udp_server.cpp
    src/upstream/dispatch.cpp
    src/upstream/doh_worker.cpp
    src/upstream/transfer.cpp
    src/upstream/upstream.cpp
)

# The daemon parses untrusted network bytes.
target_compile_options(mikrodoh PRIVATE
    -O2 -pipe
    -Wall -Wextra -Wformat=2 -Wconversion -Wshadow
    -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=2
    -D_GLIBCXX_ASSERTIONS
    -fstack-protector-strong
    -fPIE
    ${MIKRODOH_TUNE_ARGS})
target_link_libraries(mikrodoh PRIVATE -pie -Wl,-z,relro -Wl,-z,now -Wl,-z,noexecstack)
target_include_directories(mikrodoh PRIVATE src)
target_link_libraries(mikrodoh PRIVATE CURL::libcurl Threads::Threads)

if(MIKRODOH_SMALL)
    target_compile_options(mikrodoh PRIVATE -Os -flto -ffunction-sections -fdata-sections)
    target_link_options(mikrodoh PRIVATE -flto -Wl,--gc-sections -s)
endif()

install(TARGETS mikrodoh RUNTIME DESTINATION bin)
