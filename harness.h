#pragma once

// A test registry small enough to read in one sitting. A file defines cases
// with TEST(name) and they register themselves before main runs.

namespace th {

using Fn = void (*)();

struct Registrar {
    Registrar(const char* name, Fn fn);
};

void fail(const char* file, int line, const char* expr);
int  run_all();

}  // namespace th

#define TEST(name)                                    \
    static void name();                               \
    static ::th::Registrar th_reg_##name(#name, name); \
    static void name()

#define CHECK(expr)                                  \
    do {                                             \
        if (!(expr)) ::th::fail(__FILE__, __LINE__, #expr); \
    } while (0)
