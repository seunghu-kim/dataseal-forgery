#pragma once

#include <cstddef>
#include <cstdint>
#include <map>
#include <string>
#include <vector>

#include "dsf/he.hpp"
#include "dsf/matrix.hpp"
#include "dsf/sketch.hpp"

namespace dsf::he {

// Row-major layout: logical entry (i, j) lives in slot D*i + j of a single
// ciphertext, D being a padded square dimension. This is distinct from the
// column-packed layout used in he.hpp and follows Jiang et al. (ePrint
// 2018/1041) so that a whole matrix product runs inside one ciphertext.
struct RowLayout {
    std::size_t orig_rows = 0, orig_cols = 0;
    std::size_t logical_rows = 0, logical_cols = 0;
    std::size_t dim = 0;         // padded square side D
    std::size_t slot_count = 0;  // D * D

    std::vector<std::size_t> data_rows;
    std::vector<std::size_t> checksum_rows;

    std::size_t slot(std::size_t i, std::size_t j) const { return dim * i + j; }
    std::string describe_json() const;
};

RowLayout make_layout(std::size_t logical_rows, std::size_t logical_cols, std::size_t data_rows,
                      std::size_t padded_dim);
std::size_t padded_dim_for(std::size_t a, std::size_t b, std::size_t c);

struct RowCipher {
    RowLayout layout;
    Ct ct;
};

std::vector<std::int64_t> pack_rowmajor(const Context& ctx, const Mat& m, const RowLayout& layout);
Mat unpack_rowmajor(const Context& ctx, const std::vector<std::int64_t>& slots, const RowLayout& layout);

RowCipher encrypt_rowmajor(const Context& ctx, const PublicKey& pk, const Mat& m, const RowLayout& layout);
Mat decrypt_rowmajor(const Context& ctx, const PrivateKey& sk, const RowCipher& rc);

// Evaluation keys required by the Jiang matrix product for a given padded dim.
std::vector<std::int32_t> matmul_rotation_indices(std::size_t dim);

Ct cyclic_rotate(const Context& ctx, const Ct& ct, int k, std::size_t n);

// HE-MatMult of two D*D row-major ciphertexts (Jiang et al. Algorithm 2).
Ct he_matmul_square(const Context& ctx, const Ct& a, const Ct& b, std::size_t dim);

// Augmented DataSeal multiplication in row-major form: A* is (n+2) x d, B is
// d x ell, both embedded into D x D. Output keeps data rows AB, checksum rows
// w^T B and g^T B.
RowCipher matmul_augmented(const Context& ctx, const RowCipher& a_star, const RowCipher& b,
                           std::size_t out_cols);

RowCipher add_rowmajor(const Context& ctx, const RowCipher& a, const RowCipher& b);
RowCipher add_plain_rowmajor(const Context& ctx, const RowCipher& a, const Mat& c);
RowCipher square_rowmajor(const Context& ctx, const RowCipher& a);

// Rotation offsets used by public_right_matmul for an inner dimension `inner`
// and output column count `out_cols`: all distinct k - j with k in [0, inner),
// j in [0, out_cols), excluding 0.
std::vector<std::int32_t> public_matmul_rotation_indices(std::size_t inner, std::size_t out_cols);

// Enc(A) -> Enc(A B) with B public, in row-major packing. Implemented as a
// block-diagonal linear transform: rotations by k-j, plaintext coefficient
// masks holding B entries, and additions. No ciphertext-ciphertext product.
// Checksum rows are carried as ordinary rows. depth: one plaintext multiply.
RowCipher public_right_matmul(const Context& ctx, const RowCipher& a, const Mat& b, std::size_t out_cols,
                              std::vector<std::int32_t>* used = nullptr);

// Evaluates an approved program (public right multiplications, encrypted-input
// additions, public offsets, and their compositions) on row-major inputs using
// public_right_matmul. No ciphertext-ciphertext product.
RowCipher eval_program_rowmajor(const Context& ctx, const std::map<std::string, RowCipher>& inputs,
                                const Program& prog);

// Union of rotation offsets every public right multiplication in the program
// needs, so one key set covers the whole program.
std::vector<std::int32_t> program_rotation_indices(const Program& prog);

}  // namespace dsf::he
