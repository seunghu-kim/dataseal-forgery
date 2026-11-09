#include "dsf/rng.hpp"

#include <stdexcept>

#if defined(__APPLE__)
#include <sys/random.h>
#endif
#include <unistd.h>

namespace dsf {

std::uint64_t OsRng::next_u64() {
    std::uint64_t x = 0;
    if (getentropy(&x, sizeof(x)) != 0) throw std::runtime_error("getentropy failed");
    return x;
}

namespace {

std::uint64_t splitmix64(std::uint64_t& x) {
    std::uint64_t z = (x += 0x9e3779b97f4a7c15ULL);
    z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9ULL;
    z = (z ^ (z >> 27)) * 0x94d049bb133111ebULL;
    return z ^ (z >> 31);
}

std::uint64_t rotl(std::uint64_t x, int k) { return (x << k) | (x >> (64 - k)); }

}  // namespace

SeededRng::SeededRng(std::uint64_t seed) {
    for (auto& s : s_) s = splitmix64(seed);
}

std::uint64_t SeededRng::next_u64() {
    std::uint64_t r = rotl(s_[1] * 5, 7) * 9;
    std::uint64_t t = s_[1] << 17;
    s_[2] ^= s_[0];
    s_[3] ^= s_[1];
    s_[1] ^= s_[2];
    s_[0] ^= s_[3];
    s_[2] ^= t;
    s_[3] = rotl(s_[3], 45);
    return r;
}

Elem uniform_elem(const Field& f, Rng& rng) {
    std::uint64_t p = f.p();
    const std::uint64_t limit = (UINT64_MAX / p) * p;
    for (;;) {
        std::uint64_t x = rng.next_u64();
        if (x < limit) return x % p;
    }
}

Elem uniform_nonzero_elem(const Field& f, Rng& rng) {
    for (;;) {
        Elem x = uniform_elem(f, rng);
        if (x != 0) return x;
    }
}

Vec uniform_vec(const Field& f, std::size_t n, Rng& rng) {
    Vec v(n);
    for (auto& x : v) x = uniform_elem(f, rng);
    return v;
}

}  // namespace dsf
