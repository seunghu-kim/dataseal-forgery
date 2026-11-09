#include "dsf/matrix.hpp"

#include <stdexcept>
#include <utility>

namespace dsf {

namespace {

void require(bool cond, const char* msg) {
    if (!cond) throw std::invalid_argument(msg);
}

}  // namespace

Mat Mat::from_ints(const Field& f, std::initializer_list<std::initializer_list<std::int64_t>> rows) {
    std::size_t r = rows.size();
    std::size_t c = r ? rows.begin()->size() : 0;
    Mat m(r, c);
    std::size_t i = 0;
    for (const auto& row : rows) {
        require(row.size() == c, "ragged matrix literal");
        std::size_t j = 0;
        for (std::int64_t x : row) m.at(i, j++) = f.from_int(x);
        ++i;
    }
    return m;
}

Mat Mat::from_columns(const std::vector<Vec>& cols) {
    std::size_t c = cols.size();
    std::size_t r = c ? cols[0].size() : 0;
    Mat m(r, c);
    for (std::size_t j = 0; j < c; ++j) m.set_col(j, cols[j]);
    return m;
}

Vec Mat::row(std::size_t i) const {
    require(i < rows_, "row index out of range");
    return Vec(a_.begin() + static_cast<std::ptrdiff_t>(i * cols_),
               a_.begin() + static_cast<std::ptrdiff_t>((i + 1) * cols_));
}

Vec Mat::col(std::size_t j) const {
    require(j < cols_, "column index out of range");
    Vec v(rows_);
    for (std::size_t i = 0; i < rows_; ++i) v[i] = at(i, j);
    return v;
}

void Mat::set_row(std::size_t i, const Vec& v) {
    require(i < rows_ && v.size() == cols_, "set_row shape mismatch");
    for (std::size_t j = 0; j < cols_; ++j) at(i, j) = v[j];
}

void Mat::set_col(std::size_t j, const Vec& v) {
    require(j < cols_ && v.size() == rows_, "set_col shape mismatch");
    for (std::size_t i = 0; i < rows_; ++i) at(i, j) = v[i];
}

Mat Mat::top_rows(std::size_t k) const {
    require(k <= rows_, "top_rows out of range");
    Mat m(k, cols_);
    for (std::size_t i = 0; i < k; ++i)
        for (std::size_t j = 0; j < cols_; ++j) m.at(i, j) = at(i, j);
    return m;
}

Mat Mat::append_rows(const std::vector<Vec>& extra) const {
    Mat m(rows_ + extra.size(), cols_);
    for (std::size_t i = 0; i < rows_; ++i)
        for (std::size_t j = 0; j < cols_; ++j) m.at(i, j) = at(i, j);
    for (std::size_t k = 0; k < extra.size(); ++k) m.set_row(rows_ + k, extra[k]);
    return m;
}

Mat mat_add(const Field& f, const Mat& a, const Mat& b) {
    require(a.rows() == b.rows() && a.cols() == b.cols(), "mat_add shape mismatch");
    Mat r(a.rows(), a.cols());
    for (std::size_t i = 0; i < a.rows(); ++i)
        for (std::size_t j = 0; j < a.cols(); ++j) r.at(i, j) = f.add(a.at(i, j), b.at(i, j));
    return r;
}

Mat mat_sub(const Field& f, const Mat& a, const Mat& b) {
    require(a.rows() == b.rows() && a.cols() == b.cols(), "mat_sub shape mismatch");
    Mat r(a.rows(), a.cols());
    for (std::size_t i = 0; i < a.rows(); ++i)
        for (std::size_t j = 0; j < a.cols(); ++j) r.at(i, j) = f.sub(a.at(i, j), b.at(i, j));
    return r;
}

Mat mat_mul(const Field& f, const Mat& a, const Mat& b) {
    require(a.cols() == b.rows(), "mat_mul shape mismatch");
    Mat r(a.rows(), b.cols());
    for (std::size_t i = 0; i < a.rows(); ++i)
        for (std::size_t j = 0; j < b.cols(); ++j) {
            Elem s = 0;
            for (std::size_t l = 0; l < a.cols(); ++l) s = f.add(s, f.mul(a.at(i, l), b.at(l, j)));
            r.at(i, j) = s;
        }
    return r;
}

Mat mat_scale(const Field& f, Elem c, const Mat& a) {
    Mat r(a.rows(), a.cols());
    for (std::size_t i = 0; i < a.rows(); ++i)
        for (std::size_t j = 0; j < a.cols(); ++j) r.at(i, j) = f.mul(c, a.at(i, j));
    return r;
}

Mat hadamard(const Field& f, const Mat& a, const Mat& b) {
    require(a.rows() == b.rows() && a.cols() == b.cols(), "hadamard shape mismatch");
    Mat r(a.rows(), a.cols());
    for (std::size_t i = 0; i < a.rows(); ++i)
        for (std::size_t j = 0; j < a.cols(); ++j) r.at(i, j) = f.mul(a.at(i, j), b.at(i, j));
    return r;
}

Mat square(const Field& f, const Mat& a) { return hadamard(f, a, a); }

Mat transpose(const Mat& a) {
    Mat r(a.cols(), a.rows());
    for (std::size_t i = 0; i < a.rows(); ++i)
        for (std::size_t j = 0; j < a.cols(); ++j) r.at(j, i) = a.at(i, j);
    return r;
}

Vec mat_vec(const Field& f, const Mat& a, const Vec& x) {
    require(a.cols() == x.size(), "mat_vec shape mismatch");
    Vec r(a.rows(), 0);
    for (std::size_t i = 0; i < a.rows(); ++i)
        for (std::size_t j = 0; j < a.cols(); ++j) r[i] = f.add(r[i], f.mul(a.at(i, j), x[j]));
    return r;
}

Vec mat_t_vec(const Field& f, const Mat& a, const Vec& x) {
    require(a.rows() == x.size(), "mat_t_vec shape mismatch");
    Vec r(a.cols(), 0);
    for (std::size_t i = 0; i < a.rows(); ++i)
        for (std::size_t j = 0; j < a.cols(); ++j) r[j] = f.add(r[j], f.mul(a.at(i, j), x[i]));
    return r;
}

Vec column_products(const Field& f, const Mat& a) {
    Vec r(a.cols(), 1 % f.p());
    for (std::size_t i = 0; i < a.rows(); ++i)
        for (std::size_t j = 0; j < a.cols(); ++j) r[j] = f.mul(r[j], a.at(i, j));
    return r;
}

std::size_t rank(const Field& f, Mat a) {
    std::size_t r = 0;
    for (std::size_t c = 0; c < a.cols() && r < a.rows(); ++c) {
        std::size_t piv = r;
        while (piv < a.rows() && a.at(piv, c) == 0) ++piv;
        if (piv == a.rows()) continue;
        if (piv != r)
            for (std::size_t j = 0; j < a.cols(); ++j) std::swap(a.at(piv, j), a.at(r, j));
        Elem iv = f.inv(a.at(r, c));
        for (std::size_t i = r + 1; i < a.rows(); ++i) {
            Elem m = f.mul(a.at(i, c), iv);
            if (m == 0) continue;
            for (std::size_t j = c; j < a.cols(); ++j) a.at(i, j) = f.sub(a.at(i, j), f.mul(m, a.at(r, j)));
        }
        ++r;
    }
    return r;
}

bool is_zero(const Mat& a) {
    for (std::size_t i = 0; i < a.rows(); ++i)
        for (std::size_t j = 0; j < a.cols(); ++j)
            if (a.at(i, j) != 0) return false;
    return true;
}

}  // namespace dsf
