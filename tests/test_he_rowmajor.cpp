#include "dsf/dataseal.hpp"
#include "dsf/he.hpp"
#include "dsf/he_rowmajor.hpp"
#include "dsf/rng.hpp"
#include "harness.hpp"

using namespace dsf;

namespace {

const he::Context& ctx() {
    static he::Context c = he::Context::create({65537, 3, 0});
    return c;
}

const Field& F() { return ctx().field(); }

he::KeyPair keys_for(const std::vector<std::int32_t>& rots, bool relin) {
    return he::keygen(ctx(), {"declared_extended", relin, rots});
}

Mat sample(std::size_t r, std::size_t c, std::uint64_t seed) {
    SeededRng rng(seed);
    Mat m(r, c);
    for (std::size_t i = 0; i < r; ++i)
        for (std::size_t j = 0; j < c; ++j) m.at(i, j) = uniform_elem(F(), rng);
    return m;
}

Mat matmul_keys_result(const Mat& a, const Mat& b) { return mat_mul(F(), a, b); }

}  // namespace

TEST(rowmajor_pack_unpack_roundtrip) {
    auto k = keys_for({}, false);
    he::RowLayout lay = he::make_layout(4, 3, 2, 5);
    CHECK(lay.data_rows.size() == 2 && lay.checksum_rows.size() == 2);
    CHECK(lay.slot(1, 2) == 7 && lay.slot_count == 25);
    Mat m = Mat::from_ints(F(), {{1, -2, 3}, {0, 65536, 5}, {7, 8, 9}, {10, 11, 12}});
    auto rc = he::encrypt_rowmajor(ctx(), k.server.pk, m, lay);
    CHECK(he::decrypt_rowmajor(ctx(), k.client.sk, rc) == m);
}

TEST(rowmajor_pack_places_padding_as_zero) {
    he::RowLayout lay = he::make_layout(2, 2, 2, 4);
    Mat m = Mat::from_ints(F(), {{1, 2}, {3, 4}});
    auto slots = he::pack_rowmajor(ctx(), m, lay);
    CHECK(slots[lay.slot(0, 0)] == 1 && slots[lay.slot(1, 1)] == 4);
    for (std::size_t i = 0; i < 4; ++i)
        for (std::size_t j = 0; j < 4; ++j)
            if (i >= 2 || j >= 2) CHECK(slots[lay.slot(i, j)] == 0);
}

TEST(cyclic_rotate_is_modulo_n) {
    auto k = keys_for({1, 1 - 9, 2, 2 - 9}, false);
    const std::size_t n = 9;
    std::vector<std::int64_t> v(ctx().slots(), 0);
    for (std::size_t i = 0; i < n; ++i) v[i] = static_cast<std::int64_t>(i + 1);
    auto ct = ctx().cc()->Encrypt(k.server.pk, ctx().cc()->MakePackedPlaintext(v));
    auto out = he::decrypt_slots(ctx(), k.client.sk, he::cyclic_rotate(ctx(), ct, 2, n));
    for (std::size_t l = 0; l < n; ++l) CHECK(out[l] == static_cast<std::int64_t>((l + 2) % n) + 1);
    for (std::size_t l = n; l < ctx().slots(); ++l) CHECK(out[l] == 0);
}

TEST(he_matmul_square_matches_plaintext) {
    for (std::size_t d : {std::size_t{2}, std::size_t{3}, std::size_t{4}}) {
        auto k = keys_for(he::matmul_rotation_indices(d), true);
        Mat a = sample(d, d, 100 + d), b = sample(d, d, 200 + d);
        he::RowLayout lay = he::make_layout(d, d, d, d);
        auto ea = he::encrypt_rowmajor(ctx(), k.server.pk, a, lay);
        auto eb = he::encrypt_rowmajor(ctx(), k.server.pk, b, lay);
        he::RowCipher prod{lay, he::he_matmul_square(ctx(), ea.ct, eb.ct, d)};
        CHECK(he::decrypt_rowmajor(ctx(), k.client.sk, prod) == matmul_keys_result(a, b));
    }
}

TEST(he_matmul_rectangular_via_padding) {
    std::size_t n = 3, d = 2, ell = 4;
    std::size_t D = he::padded_dim_for(n, d, ell);
    auto k = keys_for(he::matmul_rotation_indices(D), true);
    Mat a = sample(n, d, 7), b = sample(d, ell, 8);
    auto ea = he::encrypt_rowmajor(ctx(), k.server.pk, a, he::make_layout(n, d, n, D));
    auto eb = he::encrypt_rowmajor(ctx(), k.server.pk, b, he::make_layout(d, ell, d, D));
    he::RowLayout out = he::make_layout(n, ell, n, D);
    he::RowCipher prod{out, he::he_matmul_square(ctx(), ea.ct, eb.ct, D)};
    CHECK(he::decrypt_rowmajor(ctx(), k.client.sk, prod) == matmul_keys_result(a, b));
}

TEST(dataseal_augmented_matmul_rowmajor_verifies) {
    OsRng os;
    std::size_t n = 4, d = 3, ell = 2;
    std::size_t D = he::padded_dim_for(n + 2, d, ell);
    auto k = keys_for(he::matmul_rotation_indices(D), true);
    auto enc = matmul_encode(F(), sample(n, d, 11), sample(d, ell, 12), matmul_keygen(F(), n, os));
    auto a_star = he::encrypt_rowmajor(ctx(), k.server.pk, enc.server.a_star, he::make_layout(n + 2, d, n, D));
    auto b = he::encrypt_rowmajor(ctx(), k.server.pk, enc.server.b, he::make_layout(d, ell, d, D));
    he::RowCipher prod = he::matmul_augmented(ctx(), a_star, b, ell);
    Mat out = he::decrypt_rowmajor(ctx(), k.client.sk, prod);
    CHECK(out == matmul_eval(F(), enc.server));
    for (auto mode : {MatmulVerifier::Original, MatmulVerifier::Strengthened, MatmulVerifier::Appendix})
        CHECK(matmul_verify(F(), enc.client, out, mode).accepted());
}

TEST(rowmajor_addition_preserves_checksum) {
    OsRng os;
    std::size_t n = 4, d = 3, D = he::padded_dim_for(n + 1, d, 1);
    auto k = keys_for({}, false);
    auto enc = add_encode(F(), sample(n, d, 13), sample(n, d, 14), add_keygen(F(), n, os));
    auto ea = he::encrypt_rowmajor(ctx(), k.server.pk, enc.server.a_star, he::make_layout(n + 1, d, n, D));
    auto eb = he::encrypt_rowmajor(ctx(), k.server.pk, enc.server.b_star, he::make_layout(n + 1, d, n, D));
    Mat out = he::decrypt_rowmajor(ctx(), k.client.sk, he::add_rowmajor(ctx(), ea, eb));
    CHECK(out == add_eval(F(), enc.server));
    CHECK(add_verify(F(), enc.client, out).accepted());
}

TEST(rowmajor_square_preserves_multiplicative_checksum) {
    OsRng os;
    std::size_t n = 4, d = 3, D = he::padded_dim_for(n + 1, d, 1);
    auto k = keys_for({}, true);
    auto enc = square_encode(F(), sample(n, d, 15), square_keygen(F(), d, os));
    auto ea = he::encrypt_rowmajor(ctx(), k.server.pk, enc.server.a_star, he::make_layout(n + 1, d, n, D));
    Mat out = he::decrypt_rowmajor(ctx(), k.client.sk, he::square_rowmajor(ctx(), ea));
    CHECK(out == square_eval(F(), enc.server));
    CHECK(square_verify(F(), enc.client, out).accepted());
}

TEST(rotation_index_set_is_symmetric_and_bounded) {
    for (std::size_t d : {std::size_t{2}, std::size_t{3}, std::size_t{4}, std::size_t{8}}) {
        auto idx = he::matmul_rotation_indices(d);
        std::size_t n = d * d;
        for (auto r : idx) CHECK(r > -static_cast<int>(n) && r < static_cast<int>(n) && r != 0);
        CHECK(!idx.empty());
    }
}

TEST_MAIN()
