#pragma once

#include <cstdint>
#include <vector>

namespace dsf {

__extension__ typedef unsigned __int128 u128;

using Elem = std::uint64_t;
using Vec = std::vector<Elem>;

bool is_prime_u64(std::uint64_t n);

class Field {
public:
    explicit Field(std::uint64_t p);

    std::uint64_t p() const { return p_; }

    Elem from_int(std::int64_t x) const;
    Elem from_u64(std::uint64_t x) const { return x % p_; }
    std::int64_t centered(Elem a) const;

    Elem add(Elem a, Elem b) const;
    Elem sub(Elem a, Elem b) const;
    Elem neg(Elem a) const;
    Elem mul(Elem a, Elem b) const;
    Elem pow(Elem a, std::uint64_t e) const;
    Elem inv(Elem a) const;

    bool operator==(const Field& o) const { return p_ == o.p_; }
    bool operator!=(const Field& o) const { return p_ != o.p_; }

private:
    std::uint64_t p_;
};

Vec vec_from_ints(const Field& f, const std::vector<std::int64_t>& xs);
Vec vec_add(const Field& f, const Vec& a, const Vec& b);
Vec vec_sub(const Field& f, const Vec& a, const Vec& b);
Vec vec_scale(const Field& f, Elem c, const Vec& a);
Elem dot(const Field& f, const Vec& a, const Vec& b);
bool is_zero(const Vec& a);

}  // namespace dsf
