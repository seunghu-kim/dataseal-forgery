#include "dsf/dataseal.hpp"

#include <stdexcept>

namespace dsf {

namespace {

void require(bool cond, const char* msg) {
    if (!cond) throw std::invalid_argument(msg);
}

}  // namespace

const char* to_string(MatmulVerifier v) {
    switch (v) {
        case MatmulVerifier::Original: return "dataseal_original";
        case MatmulVerifier::Strengthened: return "dataseal_strengthened";
        case MatmulVerifier::Appendix: return "dataseal_appendix";
    }
    return "unknown";
}

bool VerifyResult::accepted() const {
    if (!shape_ok) return false;
    for (const auto& c : checks)
        if (!c.second) return false;
    return true;
}

bool VerifyResult::check(const std::string& name) const {
    for (const auto& c : checks)
        if (c.first == name) return c.second;
    throw std::out_of_range("unknown check: " + name);
}

MatmulKey matmul_keygen(const Field& f, std::size_t n, OsRng& rng) {
    MatmulKey key;
    key.k = uniform_vec(f, n, rng);
    key.alpha = uniform_elem(f, rng);
    return key;
}

MatmulEncoding matmul_encode(const Field& f, const Mat& a, const Mat& b, const MatmulKey& key) {
    require(key.k.size() == a.rows(), "matmul key length must equal row count");
    require(a.cols() == b.rows(), "matmul shape mismatch");
    MatmulEncoding e;
    auto& cs = e.client;
    cs.key = key;
    cs.n = a.rows();
    cs.d = a.cols();
    cs.ell = b.cols();
    cs.w = mat_t_vec(f, a, key.k);
    cs.g = vec_scale(f, key.alpha, cs.w);
    cs.u0 = mat_t_vec(f, b, cs.w);
    cs.z = mat_t_vec(f, b, cs.g);
    e.server.a_star = a.append_rows({cs.w, cs.g});
    e.server.b = b;
    return e;
}

Mat matmul_eval(const Field& f, const MatmulServerView& sv) { return mat_mul(f, sv.a_star, sv.b); }

MatmulSplit matmul_split(const Mat& c_star, std::size_t n) {
    require(c_star.rows() == n + 2, "matmul output must have n+2 rows");
    return {c_star.top_rows(n), c_star.row(n), c_star.row(n + 1)};
}

VerifyResult matmul_verify(const Field& f, const MatmulClientState& cs, const Mat& c_star, MatmulVerifier mode) {
    VerifyResult r;
    r.shape_ok = c_star.rows() == cs.n + 2 && c_star.cols() == cs.ell;
    if (!r.shape_ok) return r;
    MatmulSplit s = matmul_split(c_star, cs.n);
    r.checks.emplace_back("weighted_checksum", mat_t_vec(f, s.c, cs.key.k) == s.u);
    switch (mode) {
        case MatmulVerifier::Original:
            r.checks.emplace_back("golden_output", s.v == cs.z);
            break;
        case MatmulVerifier::Strengthened:
            r.checks.emplace_back("expected_checksum", s.u == cs.u0);
            r.checks.emplace_back("golden_output", s.v == cs.z);
            break;
        case MatmulVerifier::Appendix:
            r.checks.emplace_back("scaled_checksum", s.v == vec_scale(f, cs.key.alpha, s.u));
            break;
    }
    return r;
}

Vec add_keygen(const Field& f, std::size_t n, OsRng& rng) { return uniform_vec(f, n, rng); }

AddEncoding add_encode(const Field& f, const Mat& a, const Mat& b, const Vec& k) {
    require(a.rows() == b.rows() && a.cols() == b.cols(), "addition shape mismatch");
    require(k.size() == a.rows(), "addition key length must equal row count");
    AddEncoding e;
    auto& cs = e.client;
    cs.k = k;
    cs.n = a.rows();
    cs.d = a.cols();
    Vec wa = mat_t_vec(f, a, k);
    Vec wb = mat_t_vec(f, b, k);
    cs.z = vec_add(f, wa, wb);
    e.server.a_star = a.append_rows({wa});
    e.server.b_star = b.append_rows({wb});
    return e;
}

Mat add_eval(const Field& f, const AddServerView& sv) { return mat_add(f, sv.a_star, sv.b_star); }

AddSplit add_split(const Mat& c_star, std::size_t n) {
    require(c_star.rows() == n + 1, "addition output must have n+1 rows");
    return {c_star.top_rows(n), c_star.row(n)};
}

VerifyResult add_verify(const Field& f, const AddClientState& cs, const Mat& c_star) {
    VerifyResult r;
    r.shape_ok = c_star.rows() == cs.n + 1 && c_star.cols() == cs.d;
    if (!r.shape_ok) return r;
    AddSplit s = add_split(c_star, cs.n);
    r.checks.emplace_back("expected_checksum", s.u == cs.z);
    r.checks.emplace_back("weighted_checksum", mat_t_vec(f, s.c, cs.k) == s.u);
    return r;
}

Vec square_keygen(const Field& f, std::size_t d, OsRng& rng) { return uniform_vec(f, d, rng); }

SquareEncoding square_encode(const Field& f, const Mat& a, const Vec& eta) {
    require(eta.size() == a.cols(), "square key length must equal column count");
    SquareEncoding e;
    auto& cs = e.client;
    cs.eta = eta;
    cs.n = a.rows();
    cs.d = a.cols();
    Vec prod = column_products(f, a);
    Vec t(cs.d);
    cs.z.resize(cs.d);
    for (std::size_t j = 0; j < cs.d; ++j) {
        t[j] = f.mul(eta[j], prod[j]);
        cs.z[j] = f.mul(t[j], t[j]);
    }
    e.server.a_star = a.append_rows({t});
    return e;
}

Mat square_eval(const Field& f, const SquareServerView& sv) { return square(f, sv.a_star); }

SquareSplit square_split(const Mat& c_star, std::size_t n) {
    require(c_star.rows() == n + 1, "square output must have n+1 rows");
    return {c_star.top_rows(n), c_star.row(n)};
}

VerifyResult square_verify(const Field& f, const SquareClientState& cs, const Mat& c_star) {
    VerifyResult r;
    r.shape_ok = c_star.rows() == cs.n + 1 && c_star.cols() == cs.d;
    if (!r.shape_ok) return r;
    SquareSplit s = square_split(c_star, cs.n);
    Vec prod = column_products(f, s.c);
    bool product_ok = true;
    for (std::size_t j = 0; j < cs.d; ++j) {
        Elem e2 = f.mul(cs.eta[j], cs.eta[j]);
        if (s.t[j] != f.mul(e2, prod[j])) product_ok = false;
    }
    r.checks.emplace_back("expected_checksum", s.t == cs.z);
    r.checks.emplace_back("output_product", product_ok);
    return r;
}

}  // namespace dsf
