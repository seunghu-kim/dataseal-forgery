#include <cstdint>

#include "dsf/field.hpp"
#include "dsf/matrix.hpp"
#include "dsf/rng.hpp"
#include "harness.hpp"

using namespace dsf;

TEST(rejects_non_prime_modulus) {
    CHECK_THROWS(Field(65536));
    CHECK_THROWS(Field(1));
    CHECK_THROWS(Field(0));
}

TEST(accepts_large_prime_modulus) {
    Field f((1ULL << 61) - 1);
    CHECK(f.p() == 2305843009213693951ULL);
}

TEST(canonical_reduction_of_negatives) {
    Field f(65537);
    CHECK(f.from_int(-1) == 65536);
    CHECK(f.from_int(-65537) == 0);
    CHECK(f.from_int(-65538) == 65536);
    CHECK(f.from_int(INT64_MIN) == f.neg(f.from_u64(static_cast<std::uint64_t>(INT64_MAX) + 1)));
    CHECK(f.from_int(INT64_MAX) == static_cast<std::uint64_t>(INT64_MAX) % 65537);
}

TEST(centered_representative_roundtrip) {
    Field f(65537);
    for (std::int64_t x : {-32768LL, -1LL, 0LL, 1LL, 32768LL}) CHECK(f.centered(f.from_int(x)) == x);
}

TEST(overflow_safe_multiplication) {
    Field f((1ULL << 61) - 1);
    Elem a = f.p() - 1;
    CHECK(f.mul(a, a) == 1);
    Elem b = (1ULL << 60) + 12345;
    Elem prod = f.mul(b, f.inv(b));
    CHECK(prod == 1);
}

TEST(inverse_nonzero_only) {
    Field f(65537);
    for (std::int64_t x = 1; x < 2000; x += 37) CHECK(f.mul(f.from_int(x), f.inv(f.from_int(x))) == 1);
    CHECK(f.mul(f.from_int(-5), f.inv(f.from_int(-5))) == 1);
    CHECK_THROWS(f.inv(0));
    CHECK_THROWS(f.inv(65537));
}

TEST(matrix_product_and_transpose) {
    Field f(65537);
    Mat a = Mat::from_ints(f, {{1, 2, 3}, {4, 5, 6}});
    Mat b = Mat::from_ints(f, {{7, 8}, {9, 10}, {11, 12}});
    Mat c = mat_mul(f, a, b);
    CHECK(c == Mat::from_ints(f, {{58, 64}, {139, 154}}));
    CHECK(transpose(mat_mul(f, a, b)) == mat_mul(f, transpose(b), transpose(a)));
    CHECK_THROWS(mat_mul(f, a, a));
}

TEST(matrix_product_wraps_modulus) {
    Field f(65537);
    Mat a = Mat::from_ints(f, {{65536, 2}, {-3, 40000}});
    Mat b = Mat::from_ints(f, {{65536, 0}, {30000, -1}});
    Mat c = mat_mul(f, a, b);
    CHECK(c.at(0, 0) == f.from_int(1 + 60000));
    CHECK(c.at(0, 1) == f.from_int(-2));
    CHECK(c.at(1, 0) == f.from_int(3 + 40000LL * 30000LL));
    CHECK(c.at(1, 1) == f.from_int(-40000));
}

TEST(hadamard_square_is_elementwise) {
    Field f(65537);
    Mat a = Mat::from_ints(f, {{1, -2}, {3, 300}});
    Mat s = square(f, a);
    CHECK(s == Mat::from_ints(f, {{1, 4}, {9, 90000}}));
    CHECK(s != mat_mul(f, a, a));
}

TEST(addition_and_transpose_vector_products) {
    Field f(65537);
    Mat a = Mat::from_ints(f, {{1, 2}, {3, 4}, {5, 6}});
    Vec k = vec_from_ints(f, {2, 3, 5});
    CHECK(mat_t_vec(f, a, k) == vec_from_ints(f, {36, 46}));
    CHECK(mat_vec(f, transpose(a), k) == mat_t_vec(f, a, k));
    CHECK(mat_add(f, a, a) == mat_scale(f, 2, a));
}

TEST(column_products) {
    Field f(65537);
    Mat a = Mat::from_ints(f, {{1, 0, -1}, {4, 7, -1}});
    CHECK(column_products(f, a) == vec_from_ints(f, {4, 0, 1}));
}

TEST(rank_diagnostics) {
    Field f(65537);
    CHECK(rank(f, Mat::from_ints(f, {{1, 0}, {2, 1}, {0, 1}})) == 2);
    CHECK(rank(f, Mat::from_ints(f, {{1, 3}, {2, 6}, {0, 0}})) == 1);
    CHECK(rank(f, Mat(3, 2)) == 0);
    CHECK(rank(f, Mat::from_ints(f, {{1, 1}, {65536, 65536}})) == 1);
}

TEST(uniform_sampling_in_range) {
    Field f(65537);
    OsRng os;
    SeededRng sr(7);
    for (int i = 0; i < 1000; ++i) {
        CHECK(uniform_elem(f, os) < f.p());
        CHECK(uniform_elem(f, sr) < f.p());
        CHECK(uniform_nonzero_elem(f, sr) != 0);
    }
}

TEST(seeded_rng_is_reproducible) {
    SeededRng a(42), b(42), c(43);
    bool differs = false;
    for (int i = 0; i < 16; ++i) {
        std::uint64_t x = a.next_u64();
        CHECK(x == b.next_u64());
        if (x != c.next_u64()) differs = true;
    }
    CHECK(differs);
}

TEST_MAIN()
