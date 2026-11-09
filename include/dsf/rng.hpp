#pragma once

#include <cstddef>
#include <cstdint>

#include "dsf/field.hpp"

namespace dsf {

class Rng {
public:
    virtual ~Rng() = default;
    virtual std::uint64_t next_u64() = 0;
};

class OsRng final : public Rng {
public:
    std::uint64_t next_u64() override;
};

// Non-cryptographic; for workload data and attack choices only, never for keys.
class SeededRng final : public Rng {
public:
    explicit SeededRng(std::uint64_t seed);
    std::uint64_t next_u64() override;

private:
    std::uint64_t s_[4];
};

Elem uniform_elem(const Field& f, Rng& rng);
Elem uniform_nonzero_elem(const Field& f, Rng& rng);
Vec uniform_vec(const Field& f, std::size_t n, Rng& rng);

}  // namespace dsf
