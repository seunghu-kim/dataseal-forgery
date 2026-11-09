#include "dsf/field.hpp"

#include <stdexcept>

namespace dsf {

namespace {

std::uint64_t mulmod(std::uint64_t a, std::uint64_t b, std::uint64_t m) {
    return static_cast<std::uint64_t>((static_cast<u128>(a) * b) % m);
}

std::uint64_t powmod(std::uint64_t a, std::uint64_t e, std::uint64_t m) {
    std::uint64_t r = 1 % m;
    a %= m;
    while (e) {
        if (e & 1) r = mulmod(r, a, m);
        a = mulmod(a, a, m);
        e >>= 1;
    }
    return r;
}

void require_same_size(const Vec& a, const Vec& b) {
    if (a.size() != b.size()) throw std::invalid_argument("vector size mismatch");
}

}  // namespace

bool is_prime_u64(std::uint64_t n) {
    if (n < 2) return false;
    for (std::uint64_t q : {2ULL, 3ULL, 5ULL, 7ULL, 11ULL, 13ULL, 17ULL, 19ULL, 23ULL, 29ULL, 31ULL, 37ULL}) {
        if (n % q == 0) return n == q;
    }
    std::uint64_t d = n - 1;
    int s = 0;
    while ((d & 1) == 0) {
        d >>= 1;
        ++s;
    }
    // Deterministic Miller-Rabin base set for all 64-bit integers.
    for (std::uint64_t a : {2ULL, 3ULL, 5ULL, 7ULL, 11ULL, 13ULL, 17ULL, 19ULL, 23ULL, 29ULL, 31ULL, 37ULL}) {
        std::uint64_t x = powmod(a, d, n);
        if (x == 1 || x == n - 1) continue;
        bool composite = true;
        for (int r = 1; r < s; ++r) {
            x = mulmod(x, x, n);
            if (x == n - 1) {
                composite = false;
                break;
            }
        }
        if (composite) return false;
    }
    return true;
}

Field::Field(std::uint64_t p) : p_(p) {
    if (p > (1ULL << 62) || !is_prime_u64(p)) throw std::invalid_argument("modulus must be a prime below 2^62");
}

Elem Field::from_int(std::int64_t x) const {
    std::int64_t m = static_cast<std::int64_t>(p_);
    std::int64_t r = x % m;
    return static_cast<Elem>(r < 0 ? r + m : r);
}

std::int64_t Field::centered(Elem a) const {
    return a > p_ / 2 ? static_cast<std::int64_t>(a) - static_cast<std::int64_t>(p_) : static_cast<std::int64_t>(a);
}

Elem Field::add(Elem a, Elem b) const {
    Elem s = a + b;
    return s >= p_ ? s - p_ : s;
}

Elem Field::sub(Elem a, Elem b) const { return a >= b ? a - b : a + p_ - b; }

Elem Field::neg(Elem a) const { return a == 0 ? 0 : p_ - a; }

Elem Field::mul(Elem a, Elem b) const { return mulmod(a, b, p_); }

Elem Field::pow(Elem a, std::uint64_t e) const { return powmod(a, e, p_); }

Elem Field::inv(Elem a) const {
    if (a % p_ == 0) throw std::domain_error("inverse of zero");
    return powmod(a, p_ - 2, p_);
}

Vec vec_from_ints(const Field& f, const std::vector<std::int64_t>& xs) {
    Vec v(xs.size());
    for (std::size_t i = 0; i < xs.size(); ++i) v[i] = f.from_int(xs[i]);
    return v;
}

Vec vec_add(const Field& f, const Vec& a, const Vec& b) {
    require_same_size(a, b);
    Vec r(a.size());
    for (std::size_t i = 0; i < a.size(); ++i) r[i] = f.add(a[i], b[i]);
    return r;
}

Vec vec_sub(const Field& f, const Vec& a, const Vec& b) {
    require_same_size(a, b);
    Vec r(a.size());
    for (std::size_t i = 0; i < a.size(); ++i) r[i] = f.sub(a[i], b[i]);
    return r;
}

Vec vec_scale(const Field& f, Elem c, const Vec& a) {
    Vec r(a.size());
    for (std::size_t i = 0; i < a.size(); ++i) r[i] = f.mul(c, a[i]);
    return r;
}

Elem dot(const Field& f, const Vec& a, const Vec& b) {
    require_same_size(a, b);
    Elem s = 0;
    for (std::size_t i = 0; i < a.size(); ++i) s = f.add(s, f.mul(a[i], b[i]));
    return s;
}

bool is_zero(const Vec& a) {
    for (Elem x : a)
        if (x != 0) return false;
    return true;
}

}  // namespace dsf
