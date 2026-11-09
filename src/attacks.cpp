#include "dsf/attacks.hpp"

#include <stdexcept>
#include <utility>

namespace dsf {

namespace {

void require(bool cond, const char* msg) {
    if (!cond) throw std::invalid_argument(msg);
}

}  // namespace

Mat attack_selective_scaling(const Field& f, const Mat& c_star, std::size_t n, Elem c) {
    require(c_star.rows() >= n + 2, "selective scaling needs data, checksum and golden rows");
    Mat out = c_star;
    for (std::size_t i = 0; i <= n; ++i)
        for (std::size_t j = 0; j < out.cols(); ++j) out.at(i, j) = f.mul(c, out.at(i, j));
    return out;
}

Vec kernel_vector(const Field& f, const Mat& in_star, std::size_t n, std::size_t col_a, std::size_t col_b) {
    require(in_star.rows() > n, "kernel attack needs a checksum row at index n");
    require(col_a < in_star.cols() && col_b < in_star.cols() && col_a != col_b, "invalid kernel columns");
    Elem w_a = in_star.at(n, col_a);
    Elem w_b = in_star.at(n, col_b);
    Vec h(n);
    for (std::size_t i = 0; i < n; ++i)
        h[i] = f.sub(f.mul(w_b, in_star.at(i, col_a)), f.mul(w_a, in_star.at(i, col_b)));
    return h;
}

Mat attack_kernel(const Field& f, const Mat& in_star, const Mat& c_star, std::size_t n, KernelChoice choice) {
    require(choice.target < c_star.cols() && c_star.rows() > n, "invalid kernel target");
    Vec h = kernel_vector(f, in_star, n, choice.col_a, choice.col_b);
    Mat out = c_star;
    for (std::size_t i = 0; i < n; ++i) out.at(i, choice.target) = f.add(out.at(i, choice.target), h[i]);
    return out;
}

Mat attack_square_permute(const Mat& c_star, std::size_t n, std::size_t r1, std::size_t r2,
                          std::optional<std::size_t> col) {
    require(r1 < n && r2 < n && r1 != r2, "permutation rows must be distinct data rows");
    Mat out = c_star;
    std::size_t j0 = col ? *col : 0;
    std::size_t j1 = col ? *col + 1 : out.cols();
    require(j1 <= out.cols(), "permutation column out of range");
    for (std::size_t j = j0; j < j1; ++j) std::swap(out.at(r1, j), out.at(r2, j));
    return out;
}

Mat attack_square_rescale(const Field& f, const Mat& c_star, std::size_t n, std::size_t col, std::size_t r1,
                          std::size_t r2, Elem gamma) {
    require(r1 < n && r2 < n && r1 != r2 && col < c_star.cols(), "invalid rescaling position");
    Mat out = c_star;
    out.at(r1, col) = f.mul(gamma, out.at(r1, col));
    out.at(r2, col) = f.mul(f.inv(gamma), out.at(r2, col));
    return out;
}

Mat attack_square_zero_column(const Mat& c_star, std::size_t n, std::size_t col) {
    require(col < c_star.cols() && c_star.rows() >= n, "invalid zero column");
    Mat out = c_star;
    for (std::size_t i = 0; i < n; ++i) out.at(i, col) = 0;
    return out;
}

Mat attack_zero_output(std::size_t rows, std::size_t cols) { return Mat(rows, cols); }

Mat attack_scale_all(const Field& f, const Mat& y, Elem c) { return mat_scale(f, c, y); }

}  // namespace dsf
