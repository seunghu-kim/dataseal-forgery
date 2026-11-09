#include <algorithm>

#include "dsf/dataseal.hpp"
#include "dsf/he.hpp"
#include "dsf/he_rowmajor.hpp"
#include "dsf/rng.hpp"
#include "harness.hpp"

using namespace dsf;

namespace {

const he::Context& ctx() {
    static he::Context c = he::Context::create({65537, 2, 0});
    return c;
}
const Field& F() { return ctx().field(); }

Mat sample(std::size_t r, std::size_t c, std::uint64_t seed) {
    SeededRng rng(seed);
    Mat m(r, c);
    for (std::size_t i = 0; i < r; ++i)
        for (std::size_t j = 0; j < c; ++j) m.at(i, j) = uniform_elem(F(), rng);
    return m;
}

he::KeyPair keys_for(std::size_t inner, std::size_t out_cols) {
    return he::keygen(ctx(), {"public_matmul", false, he::public_matmul_rotation_indices(inner, out_cols)});
}

}  // namespace

TEST(public_right_matmul_matches_plaintext_square) {
    std::size_t d = 4, D = 4;
    auto k = keys_for(d, d);
    Mat a = sample(d, d, 1), b = sample(d, d, 2);
    auto ea = he::encrypt_rowmajor(ctx(), k.server.pk, a, he::make_layout(d, d, d, D));
    ctx().counts().reset();
    auto c = he::public_right_matmul(ctx(), ea, b, d);
    CHECK(ctx().counts().mult_ct == 0);
    CHECK(he::decrypt_rowmajor(ctx(), k.client.sk, c) == mat_mul(F(), a, b));
}

TEST(public_right_matmul_rectangular_and_padding) {
    std::size_t n = 3, d = 2, ell = 4, D = 5;
    auto k = keys_for(d, ell);
    Mat a = sample(n, d, 3), b = sample(d, ell, 4);
    auto ea = he::encrypt_rowmajor(ctx(), k.server.pk, a, he::make_layout(n, d, n, D));
    auto c = he::public_right_matmul(ctx(), ea, b, ell);
    CHECK(c.layout.logical_rows == n && c.layout.logical_cols == ell && c.layout.dim == D);
    CHECK(he::decrypt_rowmajor(ctx(), k.client.sk, c) == mat_mul(F(), a, b));
}

TEST(public_right_matmul_no_ciphertext_multiplication) {
    std::size_t d = 3, D = 4;
    auto k = keys_for(d, d);
    auto ea = he::encrypt_rowmajor(ctx(), k.server.pk, sample(d, d, 5), he::make_layout(d, d, d, D));
    ctx().counts().reset();
    std::vector<std::int32_t> used;
    auto c = he::public_right_matmul(ctx(), ea, sample(d, d, 6), d, &used);
    CHECK(ctx().counts().mult_ct == 0 && ctx().counts().rotate > 0 && ctx().counts().mult_pt > 0);
    for (auto r : used) CHECK(r != 0 && r > -static_cast<int>(D) && r < static_cast<int>(D));
    (void)c;
}

TEST(public_right_matmul_preserves_augmented_checksum_rows) {
    OsRng os;
    std::size_t n = 4, d = 3, ell = 2, D = he::padded_dim_for(n + 2, d, ell);
    auto k = keys_for(d, ell);
    auto enc = matmul_encode(F(), sample(n, d, 7), sample(d, ell, 8), matmul_keygen(F(), n, os));
    auto a_star = he::encrypt_rowmajor(ctx(), k.server.pk, enc.server.a_star, he::make_layout(n + 2, d, n, D));
    auto c = he::public_right_matmul(ctx(), a_star, enc.server.b, ell);
    Mat out = he::decrypt_rowmajor(ctx(), k.client.sk, c);
    CHECK(out == matmul_eval(F(), enc.server));
    for (auto mode : {MatmulVerifier::Original, MatmulVerifier::Strengthened, MatmulVerifier::Appendix})
        CHECK(matmul_verify(F(), enc.client, out, mode).accepted());
}

TEST(public_right_matmul_depth_is_one_plaintext_multiply) {
    std::size_t d = 4, D = 4;
    auto k = keys_for(d, d);
    auto ea = he::encrypt_rowmajor(ctx(), k.server.pk, sample(d, d, 9), he::make_layout(d, d, d, D));
    std::size_t level_before = ea.ct->GetLevel();
    auto c = he::public_right_matmul(ctx(), ea, sample(d, d, 10), d);
    CHECK(c.ct->GetLevel() - level_before == 1);
}

TEST(public_right_matmul_rejects_shape_mismatch) {
    std::size_t d = 3, D = 4;
    auto k = keys_for(d, d);
    auto ea = he::encrypt_rowmajor(ctx(), k.server.pk, sample(d, d, 11), he::make_layout(d, d, d, D));
    CHECK_THROWS(he::public_right_matmul(ctx(), ea, sample(d + 1, d, 12), d));
    CHECK_THROWS(he::public_right_matmul(ctx(), ea, sample(d, d, 13), D + 1));
}

TEST(add_plain_rowmajor_matches_reference) {
    std::size_t n = 3, d = 3, D = 4;
    auto k = keys_for(d, d);
    Mat a = sample(n, d, 14), off = sample(n, d, 15);
    auto ea = he::encrypt_rowmajor(ctx(), k.server.pk, a, he::make_layout(n, d, n, D));
    auto c = he::add_plain_rowmajor(ctx(), ea, off);
    CHECK(he::decrypt_rowmajor(ctx(), k.client.sk, c) == mat_add(F(), a, off));
}

TEST_MAIN()
