#pragma once

#include <cstdio>
#include <exception>
#include <functional>
#include <string>
#include <vector>

namespace th {

struct Case {
    std::string name;
    std::function<void()> fn;
};

inline std::vector<Case>& registry() {
    static std::vector<Case> r;
    return r;
}

struct Failure {
    std::string msg;
};

struct Reg {
    Reg(const char* name, std::function<void()> fn) { registry().push_back({name, std::move(fn)}); }
};

inline int run_all() {
    int failed = 0;
    for (const auto& c : registry()) {
        try {
            c.fn();
            std::printf("[PASS] %s\n", c.name.c_str());
        } catch (const Failure& f) {
            ++failed;
            std::printf("[FAIL] %s: %s\n", c.name.c_str(), f.msg.c_str());
        } catch (const std::exception& e) {
            ++failed;
            std::printf("[FAIL] %s: exception: %s\n", c.name.c_str(), e.what());
        }
    }
    std::printf("%zu cases, %d failed\n", registry().size(), failed);
    return failed ? 1 : 0;
}

}  // namespace th

#ifdef __FILE_NAME__
#define TH_FILE __FILE_NAME__
#else
#define TH_FILE __FILE__
#endif

#define TH_CAT2(a, b) a##b
#define TH_CAT(a, b) TH_CAT2(a, b)
#define TEST(name)                                                   \
    static void TH_CAT(case_, name)();                               \
    static th::Reg TH_CAT(reg_, name)(#name, TH_CAT(case_, name));   \
    static void TH_CAT(case_, name)()

#define CHECK(cond)                                                                                     \
    do {                                                                                                \
        if (!(cond)) throw th::Failure{std::string(TH_FILE) + ":" + std::to_string(__LINE__) + ": " #cond}; \
    } while (0)

#define CHECK_THROWS(expr)                     \
    do {                                       \
        bool th_thrown = false;                \
        try {                                  \
            (void)(expr);                      \
        } catch (...) {                        \
            th_thrown = true;                  \
        }                                      \
        CHECK(th_thrown && "expected throw: " #expr); \
    } while (0)

#define TEST_MAIN() \
    int main() { return th::run_all(); }
