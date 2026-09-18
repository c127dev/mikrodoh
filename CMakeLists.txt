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

find_package(CURL REQUIRED)
find_package(Threads REQUIRED)

add_executable(mikrodoh
    src/main.cpp
    src/net.cpp
    src/cache.cpp
    src/coalesce.cpp
    src/config.cpp
    src/cpu.cpp
    src/dispatch.cpp
    src/dns.cpp
    src/doh_worker.cpp
    src/privs.cpp
    src/ratelimit.cpp
    src/sandbox.cpp
    src/server.cpp
    src/stats.cpp
    src/tcp_conn.cpp
    src/tcp_server.cpp
    src/transfer.cpp
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
target_link_libraries(mikrodoh PRIVATE CURL::libcurl Threads::Threads)

install(TARGETS mikrodoh RUNTIME DESTINATION bin)
