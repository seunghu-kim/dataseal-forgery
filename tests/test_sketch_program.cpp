#include "dsf/rng.hpp"
#include "dsf/sketch.hpp"
#include "dsf/sketch_program.hpp"
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

}  // namespace

TEST(emit_parse_roundtrip) {
    ProgramChain chain{{ProgramStep::Kind::Input, "A"},
                       {ProgramStep::Kind::MulRight, "B1"},
                       {ProgramStep::Kind::AddInput, "D"},
                       {ProgramStep::Kind::AddConst, "C0"},
                       {ProgramStep::Kind::MulRight, "B2"}};
    std::string text = emit_chain(chain);
    CHECK(text == "INPUT A\nMUL_RIGHT B1\nADD_INPUT D\nADD_CONST C0\nMUL_RIGHT B2\n");
    ProgramChain back = parse_chain(text);
    CHECK(back.size() == chain.size());
    for (std::size_t i = 0; i < chain.size(); ++i)
        CHECK(back[i].kind == chain[i].kind && back[i].label == chain[i].label);
}

TEST(parse_rejects_unknown_step) {
    CHECK_THROWS(parse_chain("INPUT A\nROTATE B\n"));
}

TEST(build_composition_matches_manual_program) {
    SketchServerView sv;
    OsRng os;
    auto cs = sketch_keygen(F, 8, 6, os);
    Mat a = sample(6, 4, 1), d = sample(6, 3, 2), b1 = sample(4, 3, 3), b2 = sample(3, 2, 4);
    sketch_register(F, cs, sv, "A", a);
    sketch_register(F, cs, sv, "D", d);
    std::map<std::string, Mat> operands{{"B1", b1}, {"B2", b2}};
    Program built = build_program({{ProgramStep::Kind::Input, "A"},
                                   {ProgramStep::Kind::MulRight, "B1"},
                                   {ProgramStep::Kind::AddInput, "D"},
                                   {ProgramStep::Kind::MulRight, "B2"}},
                                  operands);
    Program manual = (Program::input("A").mul_right(b1) + Program::input("D")).mul_right(b2);
    CHECK(sketch_eval(F, sv, built) == sketch_eval(F, sv, manual));
    CHECK(sketch_eval(F, sv, built) == mat_mul(F, mat_add(F, mat_mul(F, a, b1), d), b2));
    CHECK(sketch_verify(F, cs, sketch_prepare(F, cs, built), sketch_eval(F, sv, built)));
}

TEST(build_rejects_bad_chain) {
    CHECK_THROWS(build_program({}, {}));
    CHECK_THROWS(build_program({{ProgramStep::Kind::MulRight, "B"}}, {{"B", sample(2, 2, 1)}}));
    CHECK_THROWS(build_program({{ProgramStep::Kind::Input, "A"}, {ProgramStep::Kind::Input, "B"}}, {}));
    CHECK_THROWS(build_program({{ProgramStep::Kind::Input, "A"}, {ProgramStep::Kind::MulRight, "missing"}}, {}));
}

TEST(add_const_offset) {
    SketchServerView sv;
    OsRng os;
    auto cs = sketch_keygen(F, 8, 5, os);
    Mat a = sample(5, 4, 5), c0 = sample(5, 3, 6), b = sample(4, 3, 7);
    sketch_register(F, cs, sv, "A", a);
    Program prog = build_program({{ProgramStep::Kind::Input, "A"},
                                  {ProgramStep::Kind::MulRight, "B"},
                                  {ProgramStep::Kind::AddConst, "C0"}},
                                 {{"B", b}, {"C0", c0}});
    CHECK(sketch_eval(F, sv, prog) == mat_add(F, mat_mul(F, a, b), c0));
    CHECK(sketch_verify(F, cs, sketch_prepare(F, cs, prog), sketch_eval(F, sv, prog)));
}

TEST_MAIN()
