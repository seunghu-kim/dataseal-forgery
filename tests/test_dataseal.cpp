#include "dsf/dataseal.hpp"
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

MatmulKey fixed_matmul_key() { return {vec_from_ints(F, {2, 3, 5}), 7}; }

}  // namespace

TEST(alg1_encoding_layout_is_data_then_checksum_then_golden) {
    Mat a = Mat::from_ints(F, {{1, 0}, {2, 1}, {0, 1}});
    Mat b = Mat::from_ints(F, {{1, 2}, {3, 4}});
    auto e = matmul_encode(F, a, b, fixed_matmul_key());
    CHECK(e.server.a_star.rows() == 5);
    CHECK(e.server.a_star.row(3) == vec_from_ints(F, {8, 8}));
    CHECK(e.server.a_star.row(4) == vec_from_ints(F, {56, 56}));
    CHECK(e.client.u0 == vec_from_ints(F, {32, 48}));
    CHECK(e.client.z == vec_from_ints(F, {224, 336}));
}

TEST(alg4_honest_output_accepted_by_all_matmul_verifiers) {
    OsRng os;
    for (int trial = 0; trial < 5; ++trial) {
        Mat a = sample(6, 4, 100 + trial);
        Mat b = sample(4, 3, 200 + trial);
        auto key = matmul_keygen(F, 6, os);
        auto e = matmul_encode(F, a, b, key);
        Mat c_star = matmul_eval(F, e.server);
        CHECK(matmul_split(c_star, 6).c == mat_mul(F, a, b));
        CHECK(matmul_split(c_star, 6).u == e.client.u0);
        CHECK(matmul_split(c_star, 6).v == e.client.z);
        for (auto mode : {MatmulVerifier::Original, MatmulVerifier::Strengthened, MatmulVerifier::Appendix})
            CHECK(matmul_verify(F, e.client, c_star, mode).accepted());
    }
}

TEST(alg4_literal_row_labels_reject_honest_output_when_alpha_ne_1) {
    Mat a = Mat::from_ints(F, {{1, 0}, {2, 1}, {0, 1}});
    Mat b = Mat::from_ints(F, {{1, 2}, {3, 4}});
    auto e = matmul_encode(F, a, b, fixed_matmul_key());
    Mat c_star = matmul_eval(F, e.server);
    Vec v1_last = c_star.row(4);
    Vec v2_second_last = c_star.row(3);
    Mat c = c_star.top_rows(3);
    bool literal_ok = v2_second_last == e.client.z && mat_t_vec(F, c, e.client.key.k) == v1_last;
    CHECK(!literal_ok);
}

TEST(matmul_alpha_zero_honest_accepted) {
    Mat a = sample(4, 3, 1);
    Mat b = sample(3, 2, 2);
    auto e = matmul_encode(F, a, b, {vec_from_ints(F, {1, 2, 3, 4}), 0});
    Mat c_star = matmul_eval(F, e.server);
    CHECK(is_zero(e.client.z));
    for (auto mode : {MatmulVerifier::Original, MatmulVerifier::Strengthened, MatmulVerifier::Appendix})
        CHECK(matmul_verify(F, e.client, c_star, mode).accepted());
}

TEST(matmul_verifiers_reject_wrong_shape) {
    Mat a = sample(4, 3, 3);
    Mat b = sample(3, 2, 4);
    auto e = matmul_encode(F, a, b, {vec_from_ints(F, {1, 2, 3, 4}), 5});
    Mat c_star = matmul_eval(F, e.server);
    Mat short_out = c_star.top_rows(5);
    Mat tall_out = c_star.append_rows({Vec(2, 0)});
    CHECK(!matmul_verify(F, e.client, short_out, MatmulVerifier::Original).shape_ok);
    CHECK(!matmul_verify(F, e.client, tall_out, MatmulVerifier::Original).shape_ok);
    CHECK(!matmul_verify(F, e.client, Mat(6, 3), MatmulVerifier::Original).shape_ok);
    CHECK(matmul_verify(F, e.client, c_star, MatmulVerifier::Original).accepted());
    CHECK_THROWS(matmul_encode(F, a, b, {vec_from_ints(F, {1, 2, 3}), 5}));
}

TEST(matmul_random_tamper_of_data_rejected) {
    Mat a = sample(5, 4, 11);
    Mat b = sample(4, 3, 12);
    auto e = matmul_encode(F, a, b, {vec_from_ints(F, {3, 1, 4, 1, 5}), 9});
    Mat c_star = matmul_eval(F, e.server);
    c_star.at(2, 1) = F.add(c_star.at(2, 1), 1);
    for (auto mode : {MatmulVerifier::Original, MatmulVerifier::Strengthened, MatmulVerifier::Appendix})
        CHECK(!matmul_verify(F, e.client, c_star, mode).accepted());
}

TEST(appendix_and_original_are_distinct_checks) {
    Mat a = sample(4, 3, 21);
    Mat b = sample(3, 2, 22);
    auto e = matmul_encode(F, a, b, {vec_from_ints(F, {1, 2, 3, 4}), 5});
    Mat c_star = matmul_eval(F, e.server);
    auto ro = matmul_verify(F, e.client, c_star, MatmulVerifier::Original);
    auto rs = matmul_verify(F, e.client, c_star, MatmulVerifier::Strengthened);
    auto ra = matmul_verify(F, e.client, c_star, MatmulVerifier::Appendix);
    CHECK(ro.checks.size() == 2 && rs.checks.size() == 3 && ra.checks.size() == 2);
    CHECK_THROWS(ra.check("golden_output"));
    CHECK_THROWS(ro.check("expected_checksum"));
    CHECK_THROWS(ro.check("scaled_checksum"));
}

TEST(alg2_alg5_addition_honest_accepted) {
    OsRng os;
    for (int trial = 0; trial < 5; ++trial) {
        Mat a = sample(5, 4, 300 + trial);
        Mat b = sample(5, 4, 400 + trial);
        Vec k = add_keygen(F, 5, os);
        auto e = add_encode(F, a, b, k);
        Mat c_star = add_eval(F, e.server);
        CHECK(add_split(c_star, 5).c == mat_add(F, a, b));
        CHECK(add_verify(F, e.client, c_star).accepted());
    }
}

TEST(addition_rejects_tamper_and_shape) {
    Mat a = sample(3, 2, 31);
    Mat b = sample(3, 2, 32);
    auto e = add_encode(F, a, b, vec_from_ints(F, {2, 3, 5}));
    Mat c_star = add_eval(F, e.server);
    Mat bad = c_star;
    bad.at(0, 0) = F.add(bad.at(0, 0), 1);
    CHECK(!add_verify(F, e.client, bad).accepted());
    Mat bad_both = bad;
    bad_both.at(3, 0) = F.add(bad_both.at(3, 0), 2);
    CHECK(!add_verify(F, e.client, bad_both).accepted());
    CHECK(!add_verify(F, e.client, c_star.top_rows(3)).shape_ok);
    CHECK_THROWS(add_encode(F, a, sample(3, 3, 1), vec_from_ints(F, {2, 3, 5})));
}

TEST(alg3_square_encoding_uses_column_products) {
    Mat a = Mat::from_ints(F, {{1, 2}, {4, 3}});
    Vec eta = vec_from_ints(F, {3, 5});
    auto e = square_encode(F, a, eta);
    CHECK(e.server.a_star.row(2) == vec_from_ints(F, {12, 30}));
    CHECK(e.client.z == vec_from_ints(F, {144, 900}));
}

TEST(alg6_corrected_square_honest_accepted) {
    OsRng os;
    for (int trial = 0; trial < 5; ++trial) {
        Mat a = sample(4, 3, 500 + trial);
        Vec eta = square_keygen(F, 3, os);
        auto e = square_encode(F, a, eta);
        Mat c_star = square_eval(F, e.server);
        CHECK(square_split(c_star, 4).c == square(F, a));
        CHECK(square_verify(F, e.client, c_star).accepted());
    }
}

TEST(alg6_literal_input_reading_rejects_honest_output) {
    Mat a = Mat::from_ints(F, {{1, 2}, {4, 3}});
    Vec eta = vec_from_ints(F, {3, 5});
    auto e = square_encode(F, a, eta);
    Mat c_star = square_eval(F, e.server);
    Vec t = c_star.row(2);
    Vec prod_input = column_products(F, a);
    bool literal_ok = true;
    for (std::size_t j = 0; j < 2; ++j)
        if (t[j] != F.mul(F.mul(eta[j], eta[j]), prod_input[j])) literal_ok = false;
    CHECK(!literal_ok);
    CHECK(square_verify(F, e.client, c_star).accepted());
}

TEST(square_rejects_single_entry_tamper) {
    Mat a = Mat::from_ints(F, {{1, 2}, {4, 3}});
    auto e = square_encode(F, a, vec_from_ints(F, {3, 5}));
    Mat c_star = square_eval(F, e.server);
    c_star.at(0, 1) = F.add(c_star.at(0, 1), 1);
    CHECK(!square_verify(F, e.client, c_star).accepted());
    CHECK(!square_verify(F, e.client, c_star.top_rows(2)).shape_ok);
}

TEST_MAIN()
