#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <vector>

#include "dsf/attacks.hpp"
#include "dsf/dataseal.hpp"
#include "dsf/he.hpp"
#include "dsf/he_attacks.hpp"
#include "dsf/he_rowmajor.hpp"
#include "dsf/judge.hpp"
#include "harness.hpp"

using namespace dsf;

namespace {

const he::Context& ctx() {
    // A separate experimental context. This does not modify the repository's
    // existing default and leaves headroom for ciphertext-level transformations.
    static he::Context c = he::Context::create({65537, 5, 0});
    return c;
}

const Field& f() { return ctx().field(); }

const he::KeyPair& keys5() {
    static he::KeyPair k = he::keygen(
        ctx(), {"jiang_matmul_keys_only", true, he::matmul_rotation_indices(5)});
    return k;
}

const he::KeyPair& keys6() {
    static he::KeyPair k = he::keygen(
        ctx(), {"jiang_matmul_keys_only", true, he::matmul_rotation_indices(6)});
    return k;
}

const Mat& fixture_a() {
    static const Mat value = Mat::from_ints(f(), {{1, 0}, {2, 1}, {0, 1}});
    return value;
}
const Mat& fixture_b() {
    static const Mat value = Mat::from_ints(f(), {{1, 2}, {3, 4}});
    return value;
}
const Vec& fixture_k() {
    static const Vec value = vec_from_ints(f(), {2, 3, 5});
    return value;
}
const std::size_t N = 3;
const std::size_t D = 5;

he::RowCipher encode_rowmajor(const he::KeyPair& keys, const Mat& matrix,
                               std::size_t data_rows, std::size_t dim) {
    return he::encrypt_rowmajor(ctx(), keys.server.pk, matrix,
                                he::make_layout(matrix.rows(), matrix.cols(), data_rows, dim));
}

void require_matmul_only(const he::RotationAudit& trace, std::size_t dim) {
    auto matmul_rots = he::matmul_rotation_indices(dim);
    for (auto r : trace.used)
        CHECK(std::binary_search(matmul_rots.begin(), matmul_rots.end(), r));
}

Attempt attempt_matmul(const MatmulEncoding& e, const he::RowCipher& honest,
                       const he::RowCipher& changed, MatmulVerifier mode,
                       const he::KeyPair& keys) {
    Mat c0 = he::decrypt_rowmajor(ctx(), keys.client.sk, honest);
    Mat c1 = he::decrypt_rowmajor(ctx(), keys.client.sk, changed);
    return judge(matmul_verify(f(), e.client, c1, mode).accepted(), c1, c0,
                 c1.top_rows(e.client.n), mat_mul(f(), e.server.a_star.top_rows(e.client.n), e.server.b));
}

Attempt attempt_square(const SquareEncoding& e, const he::RowCipher& honest,
                       const he::RowCipher& changed, const he::KeyPair& keys) {
    Mat c0 = he::decrypt_rowmajor(ctx(), keys.client.sk, honest);
    Mat c1 = he::decrypt_rowmajor(ctx(), keys.client.sk, changed);
    return judge(square_verify(f(), e.client, c1).accepted(), c1, c0,
                 c1.top_rows(e.client.n), square(f(), e.server.a_star.top_rows(e.client.n)));
}

}  // namespace

TEST(he_attack_matmul_keys_cover_required_shifts) {
    for (std::size_t dim : {std::size_t{3}, std::size_t{4}, std::size_t{5}, std::size_t{6}, std::size_t{8}}) {
        auto rotations = he::matmul_rotation_indices(dim);
        for (std::size_t j = 1; j < dim; ++j) {
            CHECK(std::binary_search(rotations.begin(), rotations.end(), static_cast<std::int32_t>(j)));
            CHECK(std::binary_search(rotations.begin(), rotations.end(), -static_cast<std::int32_t>(j)));
            CHECK(std::binary_search(rotations.begin(), rotations.end(), static_cast<std::int32_t>(j * dim)));
            CHECK(std::binary_search(rotations.begin(), rotations.end(), -static_cast<std::int32_t>(j * dim)));
        }
    }
}

TEST(he_attack_kernel_cipher_matches_plaintext_vector) {
    auto e = matmul_encode(f(), fixture_a(), fixture_b(), {fixture_k(), 7});
    he::RowCipher input = encode_rowmajor(keys5(), e.server.a_star, N, D);
    he::RotationAudit audit;
    KernelChoice choice{0, 1, 1};
    he::Ct h = he::encrypted_kernel_column(ctx(), input, keys5().server.caps, N, choice, &audit);
    Mat got = he::decrypt_rowmajor(ctx(), keys5().client.sk, {input.layout, h});
    Mat want(N + 2, fixture_a().cols());
    Vec expected = kernel_vector(f(), e.server.a_star, N, 0, 1);
    CHECK(!is_zero(expected));
    for (std::size_t i = 0; i < N; ++i) want.at(i, choice.target) = expected[i];
    CHECK(got == want);
    require_matmul_only(audit, D);
    CHECK(!audit.used.empty());
}

TEST(he_attack_kernel_matmul_original_and_strengthened) {
    auto e = matmul_encode(f(), fixture_a(), fixture_b(), {fixture_k(), 7});
    auto in = encode_rowmajor(keys5(), e.server.a_star, N, D);
    auto right = encode_rowmajor(keys5(), e.server.b, fixture_b().rows(), D);
    auto honest = he::matmul_augmented(ctx(), in, right, fixture_b().cols());
    he::RotationAudit audit;
    auto changed = he::kernel_adjusted_output(ctx(), in, honest,
                                               keys5().server.caps, N, {0, 1, 0}, &audit);
    Mat changed_plain = he::decrypt_rowmajor(ctx(), keys5().client.sk, changed);
    CHECK(changed_plain == attack_kernel(f(), e.server.a_star, matmul_eval(f(), e.server), N, {0, 1, 0}));
    CHECK(attempt_matmul(e, honest, changed, MatmulVerifier::Original, keys5()).forged());
    CHECK(attempt_matmul(e, honest, changed, MatmulVerifier::Strengthened, keys5()).forged());
    CHECK(attempt_matmul(e, honest, changed, MatmulVerifier::Appendix, keys5()).forged());
    require_matmul_only(audit, D);
}

TEST(he_attack_selective_scaling_original_only) {
    auto e = matmul_encode(f(), fixture_a(), fixture_b(), {fixture_k(), 7});
    auto in = encode_rowmajor(keys5(), e.server.a_star, N, D);
    auto right = encode_rowmajor(keys5(), e.server.b, fixture_b().rows(), D);
    auto honest = he::matmul_augmented(ctx(), in, right, fixture_b().cols());
    auto changed = he::selective_scaling(ctx(), honest, N, 3);
    CHECK(he::decrypt_rowmajor(ctx(), keys5().client.sk, changed) ==
          attack_selective_scaling(f(), matmul_eval(f(), e.server), N, 3));
    CHECK(attempt_matmul(e, honest, changed, MatmulVerifier::Original, keys5()).forged());
    CHECK(!attempt_matmul(e, honest, changed, MatmulVerifier::Strengthened, keys5()).accepted);
}

TEST(he_attack_kernel_addition) {
    Mat b = Mat::from_ints(f(), {{4, 1}, {0, 9}, {2, 2}});
    auto e = add_encode(f(), fixture_a(), b, fixture_k());
    auto in = encode_rowmajor(keys5(), e.server.a_star, N, D);
    auto other = encode_rowmajor(keys5(), e.server.b_star, N, D);
    auto honest = he::add_rowmajor(ctx(), in, other);
    he::RotationAudit audit;
    auto changed = he::kernel_adjusted_output(ctx(), in, honest,
                                               keys5().server.caps, N, {0, 1, 1}, &audit);
    Mat c0 = he::decrypt_rowmajor(ctx(), keys5().client.sk, honest);
    Mat c1 = he::decrypt_rowmajor(ctx(), keys5().client.sk, changed);
    CHECK(c1 == attack_kernel(f(), e.server.a_star, add_eval(f(), e.server), N, {0, 1, 1}));
    CHECK(judge(add_verify(f(), e.client, c1).accepted(), c1, c0,
                c1.top_rows(N), mat_add(f(), fixture_a(), b)).forged());
    require_matmul_only(audit, D);
}

TEST(he_attack_kernel_rectangular_matrix_and_output) {
    Mat a = Mat::from_ints(f(), {{1, 0, 4}, {2, 1, 0}, {0, 1, 2}, {3, 4, 5}});
    Mat b = Mat::from_ints(f(), {{1, 2}, {3, 4}, {5, 6}});
    Vec key = vec_from_ints(f(), {1, 3, 2, 5});
    auto e = matmul_encode(f(), a, b, {key, 7});
    constexpr std::size_t n = 4, dim = 6;
    auto in = encode_rowmajor(keys6(), e.server.a_star, n, dim);
    auto other = encode_rowmajor(keys6(), e.server.b, b.rows(), dim);
    auto honest = he::matmul_augmented(ctx(), in, other, b.cols());
    he::RotationAudit audit;
    auto changed = he::kernel_adjusted_output(ctx(), in, honest, keys6().server.caps,
                                               n, {0, 2, 1}, &audit);
    CHECK(he::decrypt_rowmajor(ctx(), keys6().client.sk, changed) ==
          attack_kernel(f(), e.server.a_star, matmul_eval(f(), e.server), n, {0, 2, 1}));
    CHECK(attempt_matmul(e, honest, changed, MatmulVerifier::Strengthened, keys6()).forged());
    require_matmul_only(audit, dim);
}

TEST(he_attack_square_permute_one_column) {
    Mat a = Mat::from_ints(f(), {{2, 3}, {4, 5}, {6, 7}});
    auto e = square_encode(f(), a, vec_from_ints(f(), {7, 11}));
    auto in = encode_rowmajor(keys5(), e.server.a_star, N, D);
    auto honest = he::square_rowmajor(ctx(), in);
    he::RotationAudit audit;
    auto changed = he::square_permute(ctx(), honest, keys5().server.caps, N, 0, 2, 1, &audit);
    CHECK(he::decrypt_rowmajor(ctx(), keys5().client.sk, changed) ==
          attack_square_permute(square_eval(f(), e.server), N, 0, 2, 1));
    CHECK(attempt_square(e, honest, changed, keys5()).forged());
    require_matmul_only(audit, D);
}

TEST(he_attack_square_permute_all_columns) {
    Mat a = Mat::from_ints(f(), {{2, 3}, {4, 5}, {6, 7}});
    auto e = square_encode(f(), a, vec_from_ints(f(), {7, 11}));
    auto in = encode_rowmajor(keys5(), e.server.a_star, N, D);
    auto honest = he::square_rowmajor(ctx(), in);
    auto changed = he::square_permute(ctx(), honest, keys5().server.caps, N, 0, 1);
    CHECK(he::decrypt_rowmajor(ctx(), keys5().client.sk, changed) ==
          attack_square_permute(square_eval(f(), e.server), N, 0, 1, std::nullopt));
    CHECK(attempt_square(e, honest, changed, keys5()).forged());
}

TEST(he_attack_square_compensating_rescale) {
    Mat a = Mat::from_ints(f(), {{2, 3}, {4, 5}, {6, 7}});
    auto e = square_encode(f(), a, vec_from_ints(f(), {7, 11}));
    auto in = encode_rowmajor(keys5(), e.server.a_star, N, D);
    auto honest = he::square_rowmajor(ctx(), in);
    auto changed = he::square_rescale(ctx(), honest, N, 1, 0, 2, 3);
    CHECK(he::decrypt_rowmajor(ctx(), keys5().client.sk, changed) ==
          attack_square_rescale(f(), square_eval(f(), e.server), N, 1, 0, 2, 3));
    CHECK(attempt_square(e, honest, changed, keys5()).forged());
}

TEST(he_attack_square_zero_product_conditional) {
    Mat a = Mat::from_ints(f(), {{0, 2}, {3, 4}, {5, 6}});
    auto e = square_encode(f(), a, vec_from_ints(f(), {7, 11}));
    auto in = encode_rowmajor(keys5(), e.server.a_star, N, D);
    auto honest = he::square_rowmajor(ctx(), in);
    auto changed = he::square_zero_column(ctx(), honest, N, 0);
    CHECK(he::decrypt_rowmajor(ctx(), keys5().client.sk, changed) ==
          attack_square_zero_column(square_eval(f(), e.server), N, 0));
    CHECK(attempt_square(e, honest, changed, keys5()).forged());
}

TEST(he_attack_kernel_degenerate_columns_do_not_count_as_forgery) {
    Mat a = Mat::from_ints(f(), {{1, 3}, {2, 6}, {4, 12}});
    auto e = matmul_encode(f(), a, fixture_b(), {fixture_k(), 7});
    auto in = encode_rowmajor(keys5(), e.server.a_star, N, D);
    auto other = encode_rowmajor(keys5(), e.server.b, fixture_b().rows(), D);
    auto honest = he::matmul_augmented(ctx(), in, other, fixture_b().cols());
    auto changed = he::kernel_adjusted_output(ctx(), in, honest, keys5().server.caps, N, {0, 1, 0});
    Attempt result = attempt_matmul(e, honest, changed, MatmulVerifier::Strengthened, keys5());
    CHECK(result.accepted && result.unchanged && !result.forged());
}

TEST(he_attack_missing_capability_is_rejected) {
    auto e = matmul_encode(f(), fixture_a(), fixture_b(), {fixture_k(), 7});
    auto in = encode_rowmajor(keys5(), e.server.a_star, N, D);
    auto other = encode_rowmajor(keys5(), e.server.b, fixture_b().rows(), D);
    auto honest = he::matmul_augmented(ctx(), in, other, fixture_b().cols());
    he::Capabilities no_relin{"matmul_only", false, keys5().server.caps.rotations};
    he::Capabilities no_rotation{"matmul_only", true, {}};
    CHECK_THROWS(he::kernel_adjusted_output(ctx(), in, honest, no_relin, N, {0, 1, 0}));
    CHECK_THROWS(he::kernel_adjusted_output(ctx(), in, honest, no_rotation, N, {0, 1, 0}));
    CHECK_THROWS(he::square_permute(ctx(), honest, no_rotation, N, 0, 1));
}

TEST(he_attack_rejects_invalid_positions) {
    auto e = matmul_encode(f(), fixture_a(), fixture_b(), {fixture_k(), 7});
    auto in = encode_rowmajor(keys5(), e.server.a_star, N, D);
    auto other = encode_rowmajor(keys5(), e.server.b, fixture_b().rows(), D);
    auto honest = he::matmul_augmented(ctx(), in, other, fixture_b().cols());
    CHECK_THROWS(he::kernel_adjusted_output(ctx(), in, honest, keys5().server.caps, N, {0, 0, 0}));
    CHECK_THROWS(he::kernel_adjusted_output(ctx(), in, honest, keys5().server.caps, N, {0, 1, 3}));
    CHECK_THROWS(he::square_rescale(ctx(), honest, N, 0, 1, 1, 3));
    CHECK_THROWS(he::square_rescale(ctx(), honest, N, 0, 1, 2, 0));
}

TEST_MAIN()
