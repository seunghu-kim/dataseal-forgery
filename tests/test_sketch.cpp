#include "dsf/attacks.hpp"
#include "dsf/sketch.hpp"
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

SketchClientState test_only_deterministic_key(std::size_t r, std::size_t n, std::uint64_t seed) {
    SketchClientState cs;
    cs.k = sample(r, n, seed);
    return cs;
}

}  // namespace

TEST(sketch_rows_budget) {
    CHECK(sketch_rows_for(65537, 128, 1ULL << 32) == 10);
    CHECK(sketch_rows_for(65537, 128, 1) == 8);
    CHECK(sketch_rows_for(2, 10, 1) == 10);
    CHECK(sketch_rows_for(2, 10, 2) == 11);
    CHECK(sketch_rows_for(65537, 16, 1) == 1);
    CHECK(sketch_rows_for(65521, 16, 1) == 2);
}

TEST(sketch_honest_right_multiplication_accepted) {
    OsRng os;
    auto cs = sketch_keygen(F, 10, 6, os);
    SketchServerView sv;
    Mat a = sample(6, 4, 1);
    sketch_register(F, cs, sv, "A", a);
    Mat b = sample(4, 3, 2);
    Program prog = Program::input("A").mul_right(b);
    Mat y = sketch_eval(F, sv, prog);
    CHECK(y == mat_mul(F, a, b));
    CHECK(sketch_verify(F, cs, sketch_prepare(F, cs, prog), y));
}

TEST(sketch_affine_and_addition_accepted) {
    OsRng os;
    auto cs = sketch_keygen(F, 8, 5, os);
    SketchServerView sv;
    Mat a = sample(5, 3, 3), d = sample(5, 3, 4), c0 = sample(5, 2, 5);
    sketch_register(F, cs, sv, "A", a);
    sketch_register(F, cs, sv, "D", d);
    Mat b = sample(3, 2, 6);
    Program affine = Program::input("A").mul_right(b) + Program::constant(c0);
    Program sum = Program::input("A") + Program::input("D");
    Mat ya = sketch_eval(F, sv, affine);
    Mat ys = sketch_eval(F, sv, sum);
    CHECK(ya == mat_add(F, mat_mul(F, a, b), c0));
    CHECK(ys == mat_add(F, a, d));
    CHECK(sketch_verify(F, cs, sketch_prepare(F, cs, affine), ya));
    CHECK(sketch_verify(F, cs, sketch_prepare(F, cs, sum), ys));
}

TEST(sketch_composition_single_encoding) {
    OsRng os;
    auto cs = sketch_keygen(F, 10, 6, os);
    SketchServerView sv;
    Mat a = sample(6, 4, 7), d = sample(6, 5, 8);
    sketch_register(F, cs, sv, "A", a);
    sketch_register(F, cs, sv, "D", d);
    Mat b1 = sample(4, 5, 9), b2 = sample(5, 3, 10);
    Program prog = (Program::input("A").mul_right(b1) + Program::input("D")).mul_right(b2);
    Mat y = sketch_eval(F, sv, prog);
    CHECK(y == mat_mul(F, mat_add(F, mat_mul(F, a, b1), d), b2));
    Mat t = sketch_prepare(F, cs, prog);
    Mat t_formula = mat_mul(F, mat_add(F, mat_mul(F, cs.regs.at("A").w, b1), cs.regs.at("D").w), b2);
    CHECK(t == t_formula);
    CHECK(sketch_verify(F, cs, t, y));
}

TEST(sketch_two_programs_from_one_encoding) {
    OsRng os;
    auto cs = sketch_keygen(F, 10, 5, os);
    SketchServerView sv;
    Mat a = sample(5, 4, 11);
    sketch_register(F, cs, sv, "A", a);
    Program p1 = Program::input("A").mul_right(sample(4, 2, 12));
    Program p2 = Program::input("A").mul_right(sample(4, 4, 13)).mul_right(sample(4, 1, 14));
    Mat y1 = sketch_eval(F, sv, p1), y2 = sketch_eval(F, sv, p2);
    CHECK(sketch_verify(F, cs, sketch_prepare(F, cs, p1), y1));
    CHECK(sketch_verify(F, cs, sketch_prepare(F, cs, p2), y2));
    CHECK(!sketch_verify(F, cs, sketch_prepare(F, cs, p1), y2));
}

TEST(sketch_rejects_scaling_and_tamper_on_fixed_key) {
    auto cs = test_only_deterministic_key(10, 6, 99);
    SketchServerView sv;
    Mat a = sample(6, 4, 15);
    sketch_register(F, cs, sv, "A", a);
    Program prog = Program::input("A").mul_right(sample(4, 3, 16));
    Mat y = sketch_eval(F, sv, prog);
    Mat t = sketch_prepare(F, cs, prog);
    CHECK(!sketch_verify(F, cs, t, attack_scale_all(F, y, 3)));
    CHECK(!sketch_verify(F, cs, t, attack_scale_all(F, y, 0)));
    Mat bad = y;
    bad.at(5, 2) = F.add(bad.at(5, 2), 1);
    CHECK(!sketch_verify(F, cs, t, bad));
}

TEST(sketch_rejects_shape_mismatch) {
    auto cs = test_only_deterministic_key(4, 3, 17);
    SketchServerView sv;
    sketch_register(F, cs, sv, "A", sample(3, 2, 18));
    Program prog = Program::input("A");
    Mat t = sketch_prepare(F, cs, prog);
    CHECK(!sketch_verify(F, cs, t, Mat(3, 3)));
    CHECK(!sketch_verify(F, cs, t, Mat(4, 2)));
}

TEST(sketch_registration_and_program_validation) {
    auto cs = test_only_deterministic_key(4, 3, 19);
    SketchServerView sv;
    sketch_register(F, cs, sv, "A", sample(3, 2, 20));
    CHECK_THROWS(sketch_register(F, cs, sv, "A", sample(3, 2, 21)));
    CHECK_THROWS(sketch_register(F, cs, sv, "B", sample(4, 2, 22)));
    CHECK_THROWS(sketch_eval(F, sv, Program::input("missing")));
    CHECK_THROWS(sketch_prepare(F, cs, Program::input("missing")));
    CHECK_THROWS(sketch_prepare(F, cs, Program::constant(sample(2, 2, 23))));
    CHECK_THROWS(sketch_eval(F, sv, Program::input("A").mul_right(sample(3, 3, 24))));
}

TEST(sketch_server_view_holds_only_registered_data) {
    auto cs = test_only_deterministic_key(4, 3, 25);
    SketchServerView sv;
    Mat a = sample(3, 2, 26);
    sketch_register(F, cs, sv, "A", a);
    CHECK(sv.inputs.size() == 1);
    CHECK(sv.inputs.at("A") == a);
    CHECK(sv.inputs.at("A").rows() == 3);
}

TEST_MAIN()
