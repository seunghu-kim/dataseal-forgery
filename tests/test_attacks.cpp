#include "dsf/attacks.hpp"
#include "dsf/dataseal.hpp"
#include "dsf/judge.hpp"
#include "dsf/rng.hpp"
#include "harness.hpp"

using namespace dsf;

namespace {

const Field F(65537);

Mat sample(std::size_t r, std::size_t c, std::uint64_t seed) {
    SeededRng rng(seed);
    Mat m(r, c);
    for (std::size_t i = 0; i < r; ++i)
        for (std::size_t j = 0; j < c; ++j) m.at(i, j) = uniform_elem(F, rng);
    return m;
}

struct MatmulCase {
    MatmulEncoding e;
    Mat honest;
    Mat correct;
};

MatmulCase matmul_case(const Mat& a, const Mat& b, const MatmulKey& key) {
    auto e = matmul_encode(F, a, b, key);
    Mat honest = matmul_eval(F, e.server);
    return {e, honest, mat_mul(F, a, b)};
}

Attempt judge_matmul(const MatmulCase& mc, const Mat& out, MatmulVerifier mode) {
    bool acc = matmul_verify(F, mc.e.client, out, mode).accepted();
    return judge(acc, out, mc.honest, out.top_rows(mc.e.client.n), mc.correct);
}

Attempt judge_square(const SquareEncoding& e, const Mat& honest, const Mat& correct, const Mat& out) {
    bool acc = square_verify(F, e.client, out).accepted();
    return judge(acc, out, honest, out.top_rows(e.client.n), correct);
}

const Vec K3 = vec_from_ints(F, {2, 3, 5});
const Mat KERNEL_A = Mat::from_ints(F, {{1, 0}, {2, 1}, {0, 1}});

}  // namespace

TEST(judge_definitions) {
    Mat x = Mat::from_ints(F, {{1}});
    Mat y = Mat::from_ints(F, {{2}});
    CHECK(judge(true, y, x, y, x).forged());
    CHECK(!judge(false, y, x, y, x).forged());
    Attempt same = judge(true, x, x, x, x);
    CHECK(same.unchanged && !same.wrong_output && !same.forged());
}

TEST(selective_scaling_general_c_forges_original) {
    auto mc = matmul_case(sample(5, 4, 1), sample(4, 3, 2), {vec_from_ints(F, {1, 2, 3, 4, 5}), 11});
    CHECK(!is_zero(mc.e.client.u0));
    Mat out = attack_selective_scaling(F, mc.honest, 5, 3);
    CHECK(judge_matmul(mc, out, MatmulVerifier::Original).forged());
    CHECK(!judge_matmul(mc, out, MatmulVerifier::Strengthened).accepted);
    CHECK(!judge_matmul(mc, out, MatmulVerifier::Appendix).accepted);
}

TEST(selective_scaling_c_zero_forges_original) {
    auto mc = matmul_case(sample(5, 4, 3), sample(4, 3, 4), {vec_from_ints(F, {1, 2, 3, 4, 5}), 11});
    Mat out = attack_selective_scaling(F, mc.honest, 5, 0);
    CHECK(is_zero(out.top_rows(6)));
    CHECK(judge_matmul(mc, out, MatmulVerifier::Original).forged());
    CHECK(!judge_matmul(mc, out, MatmulVerifier::Strengthened).accepted);
}

TEST(selective_scaling_c_one_is_unchanged) {
    auto mc = matmul_case(sample(4, 3, 5), sample(3, 2, 6), {vec_from_ints(F, {1, 2, 3, 4}), 11});
    Attempt a = judge_matmul(mc, attack_selective_scaling(F, mc.honest, 4, 1), MatmulVerifier::Original);
    CHECK(a.accepted && a.unchanged && !a.forged());
}

TEST(selective_scaling_zero_projection_passes_strengthened) {
    Mat a = Mat::from_ints(F, {{3, 5}, {-2, 0}, {0, -2}});
    CHECK(is_zero(mat_t_vec(F, a, K3)));
    auto mc = matmul_case(a, Mat::from_ints(F, {{1, 2}, {3, 4}}), {K3, 7});
    CHECK(is_zero(mc.e.client.u0) && !is_zero(mc.correct));
    Mat out = attack_selective_scaling(F, mc.honest, 3, 4);
    CHECK(judge_matmul(mc, out, MatmulVerifier::Strengthened).forged());
    CHECK(judge_matmul(mc, out, MatmulVerifier::Original).forged());
}

TEST(kernel_vector_fixture) {
    auto e = matmul_encode(F, KERNEL_A, Mat::from_ints(F, {{1, 2}, {3, 4}}), {K3, 7});
    CHECK(e.client.w == vec_from_ints(F, {8, 8}));
    Vec h = kernel_vector(F, e.server.a_star, 3, 0, 1);
    CHECK(h == vec_from_ints(F, {8, 8, -8}));
    CHECK(dot(F, K3, h) == 0);
    CHECK(!is_zero(h));
}

TEST(kernel_attack_forges_strengthened_matmul) {
    auto mc = matmul_case(KERNEL_A, Mat::from_ints(F, {{1, 2}, {3, 4}}), {K3, 7});
    Mat out = attack_kernel(F, mc.e.server.a_star, mc.honest, 3, {0, 1, 0});
    CHECK(judge_matmul(mc, out, MatmulVerifier::Strengthened).forged());
    CHECK(judge_matmul(mc, out, MatmulVerifier::Original).forged());
    CHECK(judge_matmul(mc, out, MatmulVerifier::Appendix).forged());
}

TEST(kernel_attack_random_inputs_and_os_keys) {
    OsRng os;
    int forged = 0, degenerate = 0;
    for (int trial = 0; trial < 20; ++trial) {
        Mat a = sample(6, 4, 1000 + trial);
        auto mc = matmul_case(a, sample(4, 3, 2000 + trial), matmul_keygen(F, 6, os));
        Vec h = kernel_vector(F, mc.e.server.a_star, 6, 0, 1);
        CHECK(dot(F, mc.e.client.key.k, h) == 0);
        Attempt at = judge_matmul(mc, attack_kernel(F, mc.e.server.a_star, mc.honest, 6, {0, 1, 2}),
                                  MatmulVerifier::Strengthened);
        CHECK(at.accepted);
        if (is_zero(h)) {
            ++degenerate;
            CHECK(at.unchanged && !at.forged());
        } else {
            ++forged;
            CHECK(at.forged());
        }
    }
    CHECK(forged + degenerate == 20);
}

TEST(kernel_attack_proportional_columns_is_non_forgery) {
    Mat a = Mat::from_ints(F, {{1, 3}, {2, 6}, {4, 12}});
    CHECK(rank(F, a) == 1);
    auto mc = matmul_case(a, Mat::from_ints(F, {{1, 2}, {3, 4}}), {K3, 7});
    CHECK(is_zero(kernel_vector(F, mc.e.server.a_star, 3, 0, 1)));
    Attempt at = judge_matmul(mc, attack_kernel(F, mc.e.server.a_star, mc.honest, 3, {0, 1, 0}),
                              MatmulVerifier::Strengthened);
    CHECK(at.accepted && at.unchanged && !at.forged());
}

TEST(kernel_attack_zero_checksum_is_non_forgery) {
    Mat a = Mat::from_ints(F, {{3, 5}, {-2, 0}, {0, -2}});
    auto mc = matmul_case(a, Mat::from_ints(F, {{1, 2}, {3, 4}}), {K3, 7});
    CHECK(is_zero(mc.e.client.w));
    CHECK(is_zero(kernel_vector(F, mc.e.server.a_star, 3, 0, 1)));
}

TEST(kernel_attack_zero_column_is_non_forgery) {
    Mat a = Mat::from_ints(F, {{1, 0}, {2, 0}, {0, 0}});
    auto mc = matmul_case(a, Mat::from_ints(F, {{1, 2}, {3, 4}}), {K3, 7});
    CHECK(is_zero(kernel_vector(F, mc.e.server.a_star, 3, 0, 1)));
}

TEST(kernel_attack_forges_addition) {
    Mat a = KERNEL_A;
    Mat b = Mat::from_ints(F, {{4, 1}, {0, 9}, {2, 2}});
    auto e = add_encode(F, a, b, K3);
    Mat honest = add_eval(F, e.server);
    Mat out = attack_kernel(F, e.server.a_star, honest, 3, {0, 1, 1});
    bool acc = add_verify(F, e.client, out).accepted();
    Attempt at = judge(acc, out, honest, out.top_rows(3), mat_add(F, a, b));
    CHECK(at.forged());
}

TEST(kernel_attack_forges_addition_random) {
    OsRng os;
    for (int trial = 0; trial < 10; ++trial) {
        Mat a = sample(5, 3, 3000 + trial);
        Mat b = sample(5, 3, 4000 + trial);
        auto e = add_encode(F, a, b, add_keygen(F, 5, os));
        Mat honest = add_eval(F, e.server);
        Mat out = attack_kernel(F, e.server.a_star, honest, 5, {0, 1, 2});
        bool acc = add_verify(F, e.client, out).accepted();
        Attempt at = judge(acc, out, honest, out.top_rows(5), mat_add(F, a, b));
        CHECK(at.accepted);
        CHECK(at.forged() == !is_zero(kernel_vector(F, e.server.a_star, 5, 0, 1)));
    }
}

TEST(appendix_zero_output_forges) {
    auto mc = matmul_case(sample(4, 3, 7), sample(3, 2, 8), {vec_from_ints(F, {1, 2, 3, 4}), 11});
    CHECK(!is_zero(mc.correct));
    Mat out = attack_zero_output(6, 2);
    CHECK(judge_matmul(mc, out, MatmulVerifier::Appendix).forged());
    CHECK(!judge_matmul(mc, out, MatmulVerifier::Original).accepted);
    CHECK(!judge_matmul(mc, out, MatmulVerifier::Strengthened).accepted);
}

TEST(zero_key_admits_arbitrary_data_change) {
    auto mc = matmul_case(sample(3, 2, 9), sample(2, 2, 10), {Vec(3, 0), 5});
    Mat out = mc.honest;
    out.at(0, 0) = F.add(out.at(0, 0), 1);
    CHECK(judge_matmul(mc, out, MatmulVerifier::Strengthened).forged());
}

TEST(alpha_zero_selective_scaling_still_forges_original) {
    auto mc = matmul_case(sample(4, 3, 13), sample(3, 2, 14), {vec_from_ints(F, {1, 2, 3, 4}), 0});
    Mat out = attack_selective_scaling(F, mc.honest, 4, 5);
    CHECK(judge_matmul(mc, out, MatmulVerifier::Original).forged());
    CHECK(judge_matmul(mc, out, MatmulVerifier::Appendix).forged());
}

TEST(square_permutation_fixture) {
    Mat a = Mat::from_ints(F, {{1, 2}, {2, 3}});
    auto e = square_encode(F, a, vec_from_ints(F, {3, 5}));
    Mat honest = square_eval(F, e.server);
    CHECK(honest.col(0) == vec_from_ints(F, {1, 4, 36}));
    Mat out = attack_square_permute(honest, 2, 0, 1, 0);
    CHECK(out.col(0) == vec_from_ints(F, {4, 1, 36}));
    CHECK(judge_square(e, honest, square(F, a), out).forged());
}

TEST(square_permutation_all_columns) {
    Mat a = sample(4, 3, 15);
    auto e = square_encode(F, a, vec_from_ints(F, {3, 5, 7}));
    Mat honest = square_eval(F, e.server);
    Mat out = attack_square_permute(honest, 4, 1, 3, std::nullopt);
    CHECK(judge_square(e, honest, square(F, a), out).forged());
}

TEST(square_permutation_equal_values_is_unchanged) {
    Mat a = Mat::from_ints(F, {{3, 1}, {-3, 2}});
    auto e = square_encode(F, a, vec_from_ints(F, {3, 5}));
    Mat honest = square_eval(F, e.server);
    Attempt at = judge_square(e, honest, square(F, a), attack_square_permute(honest, 2, 0, 1, 0));
    CHECK(at.accepted && at.unchanged && !at.forged());
}

TEST(square_rescaling_fixture) {
    Mat a = Mat::from_ints(F, {{1, 2}, {2, 3}});
    auto e = square_encode(F, a, vec_from_ints(F, {3, 5}));
    Mat honest = square_eval(F, e.server);
    Mat out = attack_square_rescale(F, honest, 2, 0, 0, 1, 2);
    CHECK(out.col(0) == vec_from_ints(F, {2, 2, 36}));
    CHECK(judge_square(e, honest, square(F, a), out).forged());
}

TEST(square_rescaling_zero_entries_is_unchanged) {
    Mat a = Mat::from_ints(F, {{0, 2}, {0, 3}, {4, 1}});
    auto e = square_encode(F, a, vec_from_ints(F, {3, 5}));
    Mat honest = square_eval(F, e.server);
    Attempt at = judge_square(e, honest, square(F, a), attack_square_rescale(F, honest, 3, 0, 0, 1, 2));
    CHECK(at.accepted && at.unchanged && !at.forged());
}

TEST(square_conditional_zero_product_fixture) {
    Mat a = Mat::from_ints(F, {{0, 2}, {7, 3}});
    auto e = square_encode(F, a, vec_from_ints(F, {3, 5}));
    Mat honest = square_eval(F, e.server);
    Mat out = attack_square_zero_column(honest, 2, 0);
    CHECK(judge_square(e, honest, square(F, a), out).forged());
    Mat out_nonzero_col = attack_square_zero_column(honest, 2, 1);
    CHECK(!judge_square(e, honest, square(F, a), out_nonzero_col).accepted);
}

TEST_MAIN()
