#pragma once

#include <cstddef>
#include <string>
#include <utility>
#include <vector>

#include "dsf/field.hpp"
#include "dsf/matrix.hpp"
#include "dsf/rng.hpp"

namespace dsf {

enum class MatmulVerifier { Original, Strengthened, Appendix };

const char* to_string(MatmulVerifier v);

struct VerifyResult {
    bool shape_ok = false;
    std::vector<std::pair<std::string, bool>> checks;

    bool accepted() const;
    bool check(const std::string& name) const;
};

struct MatmulKey {
    Vec k;
    Elem alpha = 0;
};

struct MatmulClientState {
    MatmulKey key;
    std::size_t n = 0, d = 0, ell = 0;
    Vec w, g, u0, z;
};

struct MatmulServerView {
    Mat a_star;
    Mat b;
};

struct MatmulEncoding {
    MatmulClientState client;
    MatmulServerView server;
};

struct MatmulSplit {
    Mat c;
    Vec u, v;
};

MatmulKey matmul_keygen(const Field& f, std::size_t n, OsRng& rng);
MatmulEncoding matmul_encode(const Field& f, const Mat& a, const Mat& b, const MatmulKey& key);
Mat matmul_eval(const Field& f, const MatmulServerView& sv);
MatmulSplit matmul_split(const Mat& c_star, std::size_t n);
VerifyResult matmul_verify(const Field& f, const MatmulClientState& cs, const Mat& c_star, MatmulVerifier mode);

struct AddClientState {
    Vec k;
    std::size_t n = 0, d = 0;
    Vec z;
};

struct AddServerView {
    Mat a_star, b_star;
};

struct AddEncoding {
    AddClientState client;
    AddServerView server;
};

struct AddSplit {
    Mat c;
    Vec u;
};

Vec add_keygen(const Field& f, std::size_t n, OsRng& rng);
AddEncoding add_encode(const Field& f, const Mat& a, const Mat& b, const Vec& k);
Mat add_eval(const Field& f, const AddServerView& sv);
AddSplit add_split(const Mat& c_star, std::size_t n);
VerifyResult add_verify(const Field& f, const AddClientState& cs, const Mat& c_star);

struct SquareClientState {
    Vec eta;
    std::size_t n = 0, d = 0;
    Vec z;
};

struct SquareServerView {
    Mat a_star;
};

struct SquareEncoding {
    SquareClientState client;
    SquareServerView server;
};

struct SquareSplit {
    Mat c;
    Vec t;
};

Vec square_keygen(const Field& f, std::size_t d, OsRng& rng);
SquareEncoding square_encode(const Field& f, const Mat& a, const Vec& eta);
Mat square_eval(const Field& f, const SquareServerView& sv);
SquareSplit square_split(const Mat& c_star, std::size_t n);
VerifyResult square_verify(const Field& f, const SquareClientState& cs, const Mat& c_star);

}  // namespace dsf
