#include "dsf/he_attacks.hpp"

#include <algorithm>
#include <cstdint>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

namespace dsf::he {
namespace {

void require(bool cond, const char* message) {
    if (!cond) throw std::invalid_argument(message);
}

void check_row_cipher(const Context& ctx, const RowCipher& value) {
    require(value.ct != nullptr, "missing row-major ciphertext");
    require(value.ct->GetCryptoContext() == ctx.cc(), "ciphertext context mismatch");
    const RowLayout& l = value.layout;
    require(l.dim >= 2 && l.dim * l.dim == l.slot_count, "invalid padded layout");
    require(l.slot_count <= ctx.row_slots(), "layout must occupy one BGV rotation row");
    require(l.orig_rows <= l.logical_rows && l.logical_rows <= l.dim && l.logical_cols <= l.dim,
            "invalid logical matrix dimensions");
}

void check_data_rows(const RowLayout& l, std::size_t n, std::size_t checksums) {
    require(n > 0 && l.orig_rows == n && l.logical_rows >= n + checksums,
            "unexpected data or checksum row count");
}

std::vector<std::int64_t> all_ones(const Context& ctx) {
    return std::vector<std::int64_t>(ctx.slots(), 1);
}

std::vector<std::int64_t> all_zeros(const Context& ctx) {
    return std::vector<std::int64_t>(ctx.slots(), 0);
}

lbcrypto::Plaintext packed(const Context& ctx, const std::vector<std::int64_t>& v) {
    return ctx.cc()->MakePackedPlaintext(v);
}

struct Operations {
    const Context& ctx;
    const Capabilities& caps;
    const std::vector<std::int32_t> allowed;
    RotationAudit* audit;

    Operations(const Context& c, const Capabilities& cp, std::size_t dim, RotationAudit* a)
        : ctx(c), caps(cp), allowed(matmul_rotation_indices(dim)), audit(a) {}

    Ct rotate(const Ct& v, std::int32_t offset) const {
        if (offset == 0) return v;
        if (!std::binary_search(allowed.begin(), allowed.end(), offset))
            throw std::invalid_argument("rotation is not required by the Jiang matrix product");
        if (std::find(caps.rotations.begin(), caps.rotations.end(), offset) == caps.rotations.end())
            throw std::invalid_argument("requested rotation key is not available");
        Ct out = ctx.cc()->EvalAtIndex(v, offset);
        ++ctx.counts().rotate;
        if (audit) audit->used.push_back(offset);
        return out;
    }

    Ct mult_plain(const Ct& v, const std::vector<std::int64_t>& mask) const {
        Ct out = ctx.cc()->EvalMult(v, packed(ctx, mask));
        ++ctx.counts().mult_pt;
        return out;
    }

    Ct add(const Ct& x, const Ct& y) const {
        Ct out = ctx.cc()->EvalAdd(x, y);
        ++ctx.counts().add_ct;
        return out;
    }
};

Ct select_data_column(const Operations& op, const RowCipher& src,
                      std::size_t n, std::size_t from_col, std::size_t to_col) {
    auto mask = all_zeros(op.ctx);
    for (std::size_t i = 0; i < n; ++i) mask[src.layout.slot(i, from_col)] = 1;
    Ct selected = op.mult_plain(src.ct, mask);
    return op.rotate(selected, static_cast<std::int32_t>(from_col) -
                                   static_cast<std::int32_t>(to_col));
}

Ct broadcast_checksum(const Operations& op, const RowCipher& src,
                      std::size_t n, std::size_t checksum_col,
                      std::size_t target_col) {
    const RowLayout& lay = src.layout;
    auto mask = all_zeros(op.ctx);
    mask[lay.slot(n, checksum_col)] = 1;
    Ct single = op.mult_plain(src.ct, mask);

    // Because the selected ciphertext has exactly one nonzero logical slot,
    // raw BGV rotations suffice: no modular D*D wraparound is needed.
    const std::int32_t row_shift = static_cast<std::int32_t>(n * lay.dim);
    Ct first_row = op.rotate(single, row_shift);
    Ct aligned = op.rotate(first_row, static_cast<std::int32_t>(checksum_col) -
                                         static_cast<std::int32_t>(target_col));

    Ct out = aligned;
    for (std::size_t i = 1; i < n; ++i) {
        Ct next = op.rotate(aligned, -static_cast<std::int32_t>(i * lay.dim));
        out = op.add(out, next);
    }
    return out;
}

void check_square_parameters(const Context& ctx, const RowCipher& evaluated,
                             std::size_t n, std::size_t r1, std::size_t r2) {
    check_row_cipher(ctx, evaluated);
    check_data_rows(evaluated.layout, n, 1);
    require(r1 < n && r2 < n && r1 != r2, "invalid distinct data-row indices");
}

}  // namespace

RowCipher selective_scaling(const Context& ctx, const RowCipher& evaluated,
                            std::size_t n, Elem factor) {
    check_row_cipher(ctx, evaluated);
    check_data_rows(evaluated.layout, n, 2);
    auto mask = all_zeros(ctx);
    const std::int64_t scaled = ctx.field().centered(ctx.field().from_u64(factor));
    for (std::size_t i = 0; i < n + 2; ++i) {
        for (std::size_t j = 0; j < evaluated.layout.logical_cols; ++j)
            mask[evaluated.layout.slot(i, j)] = i <= n ? scaled : 1;
    }
    Ct transformed = ctx.cc()->EvalMult(evaluated.ct, packed(ctx, mask));
    ++ctx.counts().mult_pt;
    return {evaluated.layout, transformed};
}

Ct encrypted_kernel_column(const Context& ctx, const RowCipher& encoded_input,
                           const Capabilities& available, std::size_t n,
                           KernelChoice choice, RotationAudit* audit) {
    check_row_cipher(ctx, encoded_input);
    check_data_rows(encoded_input.layout, n, 1);
    require(choice.col_a < encoded_input.layout.logical_cols &&
                choice.col_b < encoded_input.layout.logical_cols &&
                choice.col_a != choice.col_b && choice.target < encoded_input.layout.dim,
            "kernel column choice is out of range");
    require(available.relin_key, "ciphertext multiplication key is required");

    Operations op(ctx, available, encoded_input.layout.dim, audit);
    Ct a = select_data_column(op, encoded_input, n, choice.col_a, choice.target);
    Ct b = select_data_column(op, encoded_input, n, choice.col_b, choice.target);
    Ct wb = broadcast_checksum(op, encoded_input, n, choice.col_b, choice.target);
    Ct wa = broadcast_checksum(op, encoded_input, n, choice.col_a, choice.target);

    Ct p = ctx.cc()->EvalMult(wb, a);
    Ct q = ctx.cc()->EvalMult(wa, b);
    ctx.counts().mult_ct += 2;
    Ct h = ctx.cc()->EvalSub(p, q);
    ++ctx.counts().add_ct;
    return h;
}

RowCipher kernel_adjusted_output(const Context& ctx, const RowCipher& encoded_input,
                                 const RowCipher& evaluated, const Capabilities& available,
                                 std::size_t n, KernelChoice choice, RotationAudit* audit) {
    check_row_cipher(ctx, encoded_input);
    check_row_cipher(ctx, evaluated);
    check_data_rows(evaluated.layout, n, 1);
    require(encoded_input.layout.dim == evaluated.layout.dim, "different padded dimensions");
    require(choice.target < evaluated.layout.logical_cols, "target column is outside output");
    Ct h = encrypted_kernel_column(ctx, encoded_input, available, n, choice, audit);
    Ct out = ctx.cc()->EvalAdd(evaluated.ct, h);
    ++ctx.counts().add_ct;
    return {evaluated.layout, out};
}

RowCipher square_permute(const Context& ctx, const RowCipher& evaluated,
                         const Capabilities& available, std::size_t n,
                         std::size_t r1, std::size_t r2,
                         std::optional<std::size_t> col, RotationAudit* audit) {
    check_square_parameters(ctx, evaluated, n, r1, r2);
    require(!col || *col < evaluated.layout.logical_cols, "column out of range");
    const RowLayout& lay = evaluated.layout;
    Operations op(ctx, available, lay.dim, audit);
    auto keep = all_ones(ctx);
    auto select1 = all_zeros(ctx);
    auto select2 = all_zeros(ctx);
    const std::size_t lo = col ? *col : 0;
    const std::size_t hi = col ? *col + 1 : lay.logical_cols;
    for (std::size_t j = lo; j < hi; ++j) {
        std::size_t p1 = lay.slot(r1, j), p2 = lay.slot(r2, j);
        keep[p1] = 0;
        keep[p2] = 0;
        select1[p1] = 1;
        select2[p2] = 1;
    }
    Ct rest = op.mult_plain(evaluated.ct, keep);
    Ct row1 = op.mult_plain(evaluated.ct, select1);
    Ct row2 = op.mult_plain(evaluated.ct, select2);
    const auto k = static_cast<std::int32_t>(
        static_cast<std::int64_t>(r1) * static_cast<std::int64_t>(lay.dim) -
        static_cast<std::int64_t>(r2) * static_cast<std::int64_t>(lay.dim));
    Ct moved1 = op.rotate(row1, k);
    Ct moved2 = op.rotate(row2, -k);
    return {lay, op.add(op.add(rest, moved1), moved2)};
}

RowCipher square_rescale(const Context& ctx, const RowCipher& evaluated,
                         std::size_t n, std::size_t col,
                         std::size_t r1, std::size_t r2, Elem gamma) {
    check_square_parameters(ctx, evaluated, n, r1, r2);
    require(col < evaluated.layout.logical_cols, "column out of range");
    Elem g = ctx.field().from_u64(gamma);
    require(g != 0, "rescaling scalar must be nonzero");
    auto mask = all_ones(ctx);
    mask[evaluated.layout.slot(r1, col)] = ctx.field().centered(g);
    mask[evaluated.layout.slot(r2, col)] = ctx.field().centered(ctx.field().inv(g));
    Ct out = ctx.cc()->EvalMult(evaluated.ct, packed(ctx, mask));
    ++ctx.counts().mult_pt;
    return {evaluated.layout, out};
}

RowCipher square_zero_column(const Context& ctx, const RowCipher& evaluated,
                             std::size_t n, std::size_t col) {
    check_row_cipher(ctx, evaluated);
    check_data_rows(evaluated.layout, n, 1);
    require(col < evaluated.layout.logical_cols, "column out of range");
    auto mask = all_ones(ctx);
    for (std::size_t i = 0; i < n; ++i) mask[evaluated.layout.slot(i, col)] = 0;
    Ct out = ctx.cc()->EvalMult(evaluated.ct, packed(ctx, mask));
    ++ctx.counts().mult_pt;
    return {evaluated.layout, out};
}

}  // namespace dsf::he
