#pragma once

#include <cstddef>
#include <cstdint>
#include <initializer_list>
#include <vector>

#include "dsf/field.hpp"

namespace dsf {

class Mat {
public:
    Mat() = default;
    Mat(std::size_t rows, std::size_t cols) : rows_(rows), cols_(cols), a_(rows * cols, 0) {}

    static Mat from_ints(const Field& f, std::initializer_list<std::initializer_list<std::int64_t>> rows);
    static Mat from_columns(const std::vector<Vec>& cols);

    std::size_t rows() const { return rows_; }
    std::size_t cols() const { return cols_; }

    Elem& at(std::size_t i, std::size_t j) { return a_[i * cols_ + j]; }
    Elem at(std::size_t i, std::size_t j) const { return a_[i * cols_ + j]; }

    Vec row(std::size_t i) const;
    Vec col(std::size_t j) const;
    void set_row(std::size_t i, const Vec& v);
    void set_col(std::size_t j, const Vec& v);

    Mat top_rows(std::size_t k) const;
    Mat append_rows(const std::vector<Vec>& extra) const;

    bool operator==(const Mat& o) const { return rows_ == o.rows_ && cols_ == o.cols_ && a_ == o.a_; }
    bool operator!=(const Mat& o) const { return !(*this == o); }

private:
    std::size_t rows_ = 0;
    std::size_t cols_ = 0;
    std::vector<Elem> a_;
};

Mat mat_add(const Field& f, const Mat& a, const Mat& b);
Mat mat_sub(const Field& f, const Mat& a, const Mat& b);
Mat mat_mul(const Field& f, const Mat& a, const Mat& b);
Mat mat_scale(const Field& f, Elem c, const Mat& a);
Mat hadamard(const Field& f, const Mat& a, const Mat& b);
Mat square(const Field& f, const Mat& a);
Mat transpose(const Mat& a);
Vec mat_vec(const Field& f, const Mat& a, const Vec& x);
Vec mat_t_vec(const Field& f, const Mat& a, const Vec& x);
Vec column_products(const Field& f, const Mat& a);
std::size_t rank(const Field& f, Mat a);
bool is_zero(const Mat& a);

}  // namespace dsf
