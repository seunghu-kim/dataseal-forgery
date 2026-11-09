#pragma once

#include <cstddef>
#include <optional>

#include "dsf/field.hpp"
#include "dsf/matrix.hpp"

namespace dsf {

// Every function here takes server-visible data only: encoded inputs, the honest
// output, the public row count n, and attacker-chosen public parameters.

Mat attack_selective_scaling(const Field& f, const Mat& c_star, std::size_t n, Elem c);

struct KernelChoice {
    std::size_t col_a = 0;
    std::size_t col_b = 1;
    std::size_t target = 0;
};

Vec kernel_vector(const Field& f, const Mat& in_star, std::size_t n, std::size_t col_a, std::size_t col_b);
Mat attack_kernel(const Field& f, const Mat& in_star, const Mat& c_star, std::size_t n, KernelChoice choice);

Mat attack_square_permute(const Mat& c_star, std::size_t n, std::size_t r1, std::size_t r2,
                          std::optional<std::size_t> col);
Mat attack_square_rescale(const Field& f, const Mat& c_star, std::size_t n, std::size_t col, std::size_t r1,
                          std::size_t r2, Elem gamma);
Mat attack_square_zero_column(const Mat& c_star, std::size_t n, std::size_t col);

Mat attack_zero_output(std::size_t rows, std::size_t cols);

Mat attack_scale_all(const Field& f, const Mat& y, Elem c);

}  // namespace dsf
