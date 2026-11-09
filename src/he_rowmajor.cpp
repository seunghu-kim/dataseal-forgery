#include "dsf/he_rowmajor.hpp"

#include <algorithm>
#include <functional>
#include <set>
#include <sstream>
#include <stdexcept>

namespace dsf::he {

using namespace lbcrypto;

namespace {

void require(bool cond, const std::string& msg) {
    if (!cond) throw std::invalid_argument(msg);
}

Plaintext mask_pt(const Context& ctx, const std::vector<std::int64_t>& v) { return ctx.cc()->MakePackedPlaintext(v); }

// Diagonal decomposition of a gather permutation out[l] = in[P(l)].
// Returns, keyed by rotation amount k in [0, n), the plaintext mask selecting
// the slots whose source is at (l + k) mod n.
std::vector<std::pair<int, std::vector<std::int64_t>>> gather_diagonals(
    const std::function<std::size_t(std::size_t)>& perm, std::size_t n) {
    std::vector<std::vector<std::int64_t>> by_k(n);
    for (std::size_t l = 0; l < n; ++l) {
        std::size_t src = perm(l);
        std::size_t k = (src + n - l) % n;
        if (by_k[k].empty()) by_k[k].assign(n, 0);
        by_k[k][l] = 1;
    }
    std::vector<std::pair<int, std::vector<std::int64_t>>> out;
    for (std::size_t k = 0; k < n; ++k)
        if (!by_k[k].empty()) out.emplace_back(static_cast<int>(k), std::move(by_k[k]));
    return out;
}

std::vector<std::int64_t> restrict_mask(const std::vector<std::int64_t>& diag, std::size_t lo, std::size_t hi) {
    std::vector<std::int64_t> m(diag.size(), 0);
    for (std::size_t l = lo; l < hi; ++l) m[l] = diag[l];
    return m;
}

Ct lin_trans(const Context& ctx, const Ct& ct, const std::vector<std::pair<int, std::vector<std::int64_t>>>& diags,
             std::size_t n) {
    Ct acc;
    auto accumulate = [&](const Ct& term) {
        if (!acc) {
            acc = term;
        } else {
            acc = ctx.cc()->EvalAdd(acc, term);
            ++ctx.counts().add_ct;
        }
    };
    for (const auto& [k, diag] : diags) {
        if (k == 0) {
            Plaintext pt = mask_pt(ctx, diag);
            accumulate(ctx.cc()->EvalMult(ct, pt));
            ++ctx.counts().mult_pt;
            continue;
        }
        Ct r1 = ctx.cc()->EvalAtIndex(ct, k);
        Ct r2 = ctx.cc()->EvalAtIndex(ct, k - static_cast<int>(n));
        ctx.counts().rotate += 2;
        Plaintext m1 = mask_pt(ctx, restrict_mask(diag, 0, n - static_cast<std::size_t>(k)));
        Plaintext m2 = mask_pt(ctx, restrict_mask(diag, n - static_cast<std::size_t>(k), n));
        Ct t1 = ctx.cc()->EvalMult(r1, m1);
        Ct t2 = ctx.cc()->EvalMult(r2, m2);
        ctx.counts().mult_pt += 2;
        accumulate(ctx.cc()->EvalAdd(t1, t2));
        ++ctx.counts().add_ct;
    }
    return acc;
}

std::function<std::size_t(std::size_t)> perm_sigma(std::size_t d) {
    return [d](std::size_t l) { std::size_t i = l / d, j = l % d; return d * i + (i + j) % d; };
}
std::function<std::size_t(std::size_t)> perm_tau(std::size_t d) {
    return [d](std::size_t l) { std::size_t i = l / d, j = l % d; return d * ((i + j) % d) + j; };
}
std::function<std::size_t(std::size_t)> perm_phi(std::size_t d, std::size_t k) {
    return [d, k](std::size_t l) { std::size_t i = l / d, j = l % d; return d * i + (j + k) % d; };
}
std::function<std::size_t(std::size_t)> perm_psi(std::size_t d, std::size_t k) {
    return [d, k](std::size_t l) { std::size_t i = l / d, j = l % d; return d * ((i + k) % d) + j; };
}

}  // namespace

std::size_t padded_dim_for(std::size_t a, std::size_t b, std::size_t c) {
    return std::max(a, std::max(b, c));
}

RowLayout make_layout(std::size_t logical_rows, std::size_t logical_cols, std::size_t data_rows,
                      std::size_t padded_dim) {
    require(logical_rows <= padded_dim && logical_cols <= padded_dim, "layout exceeds padded dimension");
    require(data_rows <= logical_rows, "data rows exceed logical rows");
    RowLayout lay;
    lay.orig_rows = data_rows;
    lay.orig_cols = logical_cols;
    lay.logical_rows = logical_rows;
    lay.logical_cols = logical_cols;
    lay.dim = padded_dim;
    lay.slot_count = padded_dim * padded_dim;
    for (std::size_t i = 0; i < data_rows; ++i) lay.data_rows.push_back(i);
    for (std::size_t i = data_rows; i < logical_rows; ++i) lay.checksum_rows.push_back(i);
    return lay;
}

std::string RowLayout::describe_json() const {
    std::ostringstream os;
    os << "{\"orig_rows\": " << orig_rows << ", \"orig_cols\": " << orig_cols << ", \"logical_rows\": " << logical_rows
       << ", \"logical_cols\": " << logical_cols << ", \"padded_dim\": " << dim << ", \"slot_count\": " << slot_count
       << ", \"data_rows\": " << data_rows.size() << ", \"checksum_rows\": " << checksum_rows.size() << "}";
    return os.str();
}

std::vector<std::int64_t> pack_rowmajor(const Context& ctx, const Mat& m, const RowLayout& layout) {
    require(m.rows() == layout.logical_rows && m.cols() == layout.logical_cols, "matrix shape does not match layout");
    require(layout.slot_count <= ctx.slots(), "layout does not fit into available slots");
    std::vector<std::int64_t> v(ctx.slots(), 0);
    for (std::size_t i = 0; i < m.rows(); ++i)
        for (std::size_t j = 0; j < m.cols(); ++j) v[layout.slot(i, j)] = ctx.field().centered(m.at(i, j));
    return v;
}

Mat unpack_rowmajor(const Context& ctx, const std::vector<std::int64_t>& slots, const RowLayout& layout) {
    Mat m(layout.logical_rows, layout.logical_cols);
    for (std::size_t i = 0; i < layout.logical_rows; ++i)
        for (std::size_t j = 0; j < layout.logical_cols; ++j)
            m.at(i, j) = ctx.field().from_int(slots[layout.slot(i, j)]);
    return m;
}

RowCipher encrypt_rowmajor(const Context& ctx, const PublicKey& pk, const Mat& m, const RowLayout& layout) {
    RowCipher rc{layout, ctx.cc()->Encrypt(pk, mask_pt(ctx, pack_rowmajor(ctx, m, layout)))};
    ++ctx.counts().encrypt;
    return rc;
}

Mat decrypt_rowmajor(const Context& ctx, const PrivateKey& sk, const RowCipher& rc) {
    require(rc.ct->GetCryptoContext() == ctx.cc(), "ciphertext belongs to a different crypto context");
    return unpack_rowmajor(ctx, decrypt_slots(ctx, sk, rc.ct), rc.layout);
}

Ct cyclic_rotate(const Context& ctx, const Ct& ct, int k, std::size_t n) {
    int r = ((k % static_cast<int>(n)) + static_cast<int>(n)) % static_cast<int>(n);
    if (r == 0) return ct;
    std::vector<std::int64_t> low(ctx.slots(), 0), high(ctx.slots(), 0);
    for (std::size_t l = 0; l < n - static_cast<std::size_t>(r); ++l) low[l] = 1;
    for (std::size_t l = n - static_cast<std::size_t>(r); l < n; ++l) high[l] = 1;
    Ct r1 = ctx.cc()->EvalAtIndex(ct, r);
    Ct r2 = ctx.cc()->EvalAtIndex(ct, r - static_cast<int>(n));
    ctx.counts().rotate += 2;
    Plaintext ml = mask_pt(ctx, low), mh = mask_pt(ctx, high);
    Ct out = ctx.cc()->EvalAdd(ctx.cc()->EvalMult(r1, ml), ctx.cc()->EvalMult(r2, mh));
    ctx.counts().mult_pt += 2;
    ++ctx.counts().add_ct;
    return out;
}

std::vector<std::int32_t> matmul_rotation_indices(std::size_t dim) {
    std::size_t n = dim * dim;
    std::set<std::int32_t> idx;
    auto add_perm = [&](const std::function<std::size_t(std::size_t)>& perm) {
        for (const auto& [k, diag] : gather_diagonals(perm, n)) {
            (void)diag;
            if (k == 0) continue;
            idx.insert(k);
            idx.insert(k - static_cast<int>(n));
        }
    };
    add_perm(perm_sigma(dim));
    add_perm(perm_tau(dim));
    for (std::size_t k = 1; k < dim; ++k) {
        add_perm(perm_phi(dim, k));
        add_perm(perm_psi(dim, k));
    }
    return {idx.begin(), idx.end()};
}

Ct he_matmul_square(const Context& ctx, const Ct& a, const Ct& b, std::size_t dim) {
    std::size_t n = dim * dim;
    Ct a0 = lin_trans(ctx, a, gather_diagonals(perm_sigma(dim), n), n);
    Ct b0 = lin_trans(ctx, b, gather_diagonals(perm_tau(dim), n), n);
    Ct acc = ctx.cc()->EvalMult(a0, b0);
    ++ctx.counts().mult_ct;
    for (std::size_t k = 1; k < dim; ++k) {
        Ct ak = lin_trans(ctx, a0, gather_diagonals(perm_phi(dim, k), n), n);
        Ct bk = lin_trans(ctx, b0, gather_diagonals(perm_psi(dim, k), n), n);
        acc = ctx.cc()->EvalAdd(acc, ctx.cc()->EvalMult(ak, bk));
        ++ctx.counts().mult_ct;
        ++ctx.counts().add_ct;
    }
    return acc;
}

RowCipher matmul_augmented(const Context& ctx, const RowCipher& a_star, const RowCipher& b, std::size_t out_cols) {
    require(a_star.layout.dim == b.layout.dim, "operands must share the padded dimension");
    require(a_star.layout.logical_cols == b.layout.logical_rows, "inner dimensions must match");
    std::size_t dim = a_star.layout.dim;
    Ct prod = he_matmul_square(ctx, a_star.ct, b.ct, dim);
    RowLayout out = make_layout(a_star.layout.logical_rows, out_cols, a_star.layout.orig_rows, dim);
    return {out, prod};
}

RowCipher add_rowmajor(const Context& ctx, const RowCipher& a, const RowCipher& b) {
    require(a.ct->GetCryptoContext() == ctx.cc() && b.ct->GetCryptoContext() == ctx.cc(), "crypto context mismatch");
    require(a.layout.logical_rows == b.layout.logical_rows && a.layout.logical_cols == b.layout.logical_cols &&
                a.layout.dim == b.layout.dim,
            "row-major addition shape mismatch");
    ++ctx.counts().add_ct;
    return {a.layout, ctx.cc()->EvalAdd(a.ct, b.ct)};
}

RowCipher square_rowmajor(const Context& ctx, const RowCipher& a) {
    ++ctx.counts().mult_ct;
    return {a.layout, ctx.cc()->EvalMult(a.ct, a.ct)};
}

RowCipher add_plain_rowmajor(const Context& ctx, const RowCipher& a, const Mat& c) {
    require(c.rows() == a.layout.logical_rows && c.cols() == a.layout.logical_cols, "offset shape mismatch");
    Plaintext pt = mask_pt(ctx, pack_rowmajor(ctx, c, a.layout));
    ++ctx.counts().add_pt;
    return {a.layout, ctx.cc()->EvalAdd(a.ct, pt)};
}

std::vector<std::int32_t> public_matmul_rotation_indices(std::size_t inner, std::size_t out_cols) {
    std::set<std::int32_t> idx;
    for (std::size_t k = 0; k < inner; ++k)
        for (std::size_t j = 0; j < out_cols; ++j) {
            int delta = static_cast<int>(k) - static_cast<int>(j);
            if (delta != 0) idx.insert(delta);
        }
    return {idx.begin(), idx.end()};
}

RowCipher public_right_matmul(const Context& ctx, const RowCipher& a, const Mat& b, std::size_t out_cols,
                              std::vector<std::int32_t>* used) {
    require(a.ct != nullptr && a.ct->GetCryptoContext() == ctx.cc(), "crypto context mismatch");
    const RowLayout& la = a.layout;
    const std::size_t inner = la.logical_cols;
    require(b.rows() == inner, "public matmul inner dimension mismatch");
    require(out_cols <= b.cols() && out_cols <= la.dim, "output columns exceed operand or padded dim");

    // Group contributions by rotation offset delta = k - j. For each delta the
    // coefficient mask holds B[j+delta][j] at the output slots it feeds; masks
    // zero the row-boundary-crossing slots, so one block rotation per delta is
    // exact and no ciphertext-ciphertext product is used.
    std::set<int> deltas;
    for (std::size_t k = 0; k < inner; ++k)
        for (std::size_t j = 0; j < out_cols; ++j) deltas.insert(static_cast<int>(k) - static_cast<int>(j));

    Ct acc;
    bool have_acc = false;
    auto accumulate = [&](const Ct& term) {
        if (!have_acc) {
            acc = term;
            have_acc = true;
        } else {
            acc = ctx.cc()->EvalAdd(acc, term);
            ++ctx.counts().add_ct;
        }
    };
    for (int delta : deltas) {
        std::vector<std::int64_t> mask(ctx.slots(), 0);
        bool nonzero = false;
        for (std::size_t i = 0; i < la.logical_rows; ++i)
            for (std::size_t j = 0; j < out_cols; ++j) {
                int k = static_cast<int>(j) + delta;
                if (k < 0 || k >= static_cast<int>(inner)) continue;
                Elem coeff = b.at(static_cast<std::size_t>(k), j);
                if (coeff == 0) continue;
                mask[la.slot(i, j)] = ctx.field().centered(coeff);
                nonzero = true;
            }
        if (!nonzero) continue;
        Ct rotated = a.ct;
        if (delta != 0) {
            rotated = ctx.cc()->EvalAtIndex(a.ct, delta);
            ++ctx.counts().rotate;
            if (used) used->push_back(delta);
        }
        accumulate(ctx.cc()->EvalMult(rotated, mask_pt(ctx, mask)));
        ++ctx.counts().mult_pt;
    }
    require(have_acc, "public matmul produced no terms");
    RowLayout out = make_layout(la.logical_rows, out_cols, la.orig_rows, la.dim);
    return {out, acc};
}

namespace {

struct RowValue {
    bool plain = false;
    Mat m;
    RowCipher e;
};

}  // namespace

RowCipher eval_program_rowmajor(const Context& ctx, const std::map<std::string, RowCipher>& inputs,
                                const Program& prog) {
    const Field& f = ctx.field();
    auto on_input = [&](const std::string& l) {
        auto it = inputs.find(l);
        require(it != inputs.end(), "unknown input label");
        return RowValue{false, {}, it->second};
    };
    auto on_const = [&](const Mat& c) { return RowValue{true, c, {}}; };
    auto on_add = [&](const RowValue& x, const RowValue& y) {
        if (x.plain && y.plain) return RowValue{true, mat_add(f, x.m, y.m), {}};
        if (x.plain) return RowValue{false, {}, add_plain_rowmajor(ctx, y.e, x.m)};
        if (y.plain) return RowValue{false, {}, add_plain_rowmajor(ctx, x.e, y.m)};
        return RowValue{false, {}, add_rowmajor(ctx, x.e, y.e)};
    };
    auto on_mul = [&](const RowValue& x, const Mat& b) {
        if (x.plain) return RowValue{true, mat_mul(f, x.m, b), {}};
        return RowValue{false, {}, public_right_matmul(ctx, x.e, b, b.cols())};
    };
    RowValue v = fold_program<RowValue>(prog.root(), on_input, on_const, on_add, on_mul);
    require(!v.plain, "program has no encrypted input");
    return v.e;
}

std::vector<std::int32_t> program_rotation_indices(const Program& prog) {
    std::set<std::int32_t> idx;
    std::function<void(const ProgramNode&)> walk = [&](const ProgramNode& n) {
        switch (n.kind) {
            case ProgramNode::Kind::Input:
            case ProgramNode::Kind::Constant:
                return;
            case ProgramNode::Kind::Add:
                walk(*n.lhs);
                walk(*n.rhs);
                return;
            case ProgramNode::Kind::MulRight:
                walk(*n.lhs);
                for (auto d : public_matmul_rotation_indices(n.m.rows(), n.m.cols())) idx.insert(d);
                return;
        }
    };
    walk(prog.root());
    return {idx.begin(), idx.end()};
}

}  // namespace dsf::he
