#include "dsf/dataseal.hpp"
#include "dsf/he.hpp"
#include "dsf/rng.hpp"
#include "dsf/sketch.hpp"
#include "harness.hpp"

using namespace dsf;

namespace {

const he::Context& ctx() {
    static he::Context c = he::Context::create({});
    return c;
}

const he::KeyPair& keys_minimal() {
    static he::KeyPair k = he::keygen(ctx(), {"honest_minimal", false, {}});
    return k;
}

const he::KeyPair& keys_relin() {
    static he::KeyPair k = he::keygen(ctx(), {"honest_minimal", true, {}});
    return k;
}

const Field& F() { return ctx().field(); }

Mat sample(std::size_t r, std::size_t c, std::uint64_t seed) {
    SeededRng rng(seed);
    Mat m(r, c);
    for (std::size_t i = 0; i < r; ++i)
        for (std::size_t j = 0; j < c; ++j) m.at(i, j) = uniform_elem(F(), rng);
    return m;
}

he::Ct encrypt_slots(const he::KeyPair& k, const std::vector<std::int64_t>& v) {
    return ctx().cc()->Encrypt(k.server.pk, ctx().cc()->MakePackedPlaintext(v));
}

}  // namespace

TEST(context_parameters_support_full_packing) {
    CHECK(F().p() == 65537);
    CHECK(ctx().slots() == ctx().ring_dim());
    CHECK((F().p() - 1) % (2ULL * ctx().ring_dim()) == 0);
    CHECK(ctx().row_slots() * 2 == ctx().slots());
}

TEST(rejects_non_splitting_plaintext_modulus) {
    CHECK_THROWS(he::Context::create({65521, 1, 0}));
}

TEST(one_hot_slot_roundtrip) {
    const std::size_t S = ctx().slots();
    for (std::size_t pos : {std::size_t{0}, std::size_t{1}, std::size_t{7}, ctx().row_slots() - 1, ctx().row_slots(), S - 1}) {
        std::vector<std::int64_t> v(S, 0);
        v[pos] = 5;
        auto out = he::decrypt_slots(ctx(), keys_minimal().client.sk, encrypt_slots(keys_minimal(), v));
        for (std::size_t i = 0; i < S; ++i) CHECK(out[i] == (i == pos ? 5 : 0));
    }
}

TEST(rotation_probe_is_cyclic_within_row) {
    auto k = he::keygen(ctx(), {"declared_extended", false, {1, -1}});
    const std::size_t S = ctx().slots(), R = ctx().row_slots();
    std::vector<std::int64_t> v(S, 0);
    v[0] = 3;
    v[R - 1] = 4;
    v[R] = 6;
    auto ct = encrypt_slots(k, v);
    auto left = he::decrypt_slots(ctx(), k.client.sk, ctx().cc()->EvalAtIndex(ct, 1));
    CHECK(left[R - 1] == 3 && left[R - 2] == 4 && left[S - 1] == 6);
    auto right = he::decrypt_slots(ctx(), k.client.sk, ctx().cc()->EvalAtIndex(ct, -1));
    CHECK(right[1] == 3 && right[0] == 4 && right[R + 1] == 6);
    CHECK_THROWS(ctx().cc()->EvalAtIndex(ct, 2));
}

TEST(matrix_roundtrip_exact) {
    Mat a = Mat::from_ints(F(), {{0, -1, 32768}, {-32768, 65536, 12345}, {1, 2, 3}});
    auto e = he::encrypt_matrix(ctx(), keys_minimal().server.pk, a);
    CHECK(e.col.size() == 3);
    CHECK(he::decrypt_matrix(ctx(), keys_minimal().client.sk, e) == a);
}

TEST(rejects_capacity_overflow) {
    CHECK_THROWS(he::encrypt_matrix(ctx(), keys_minimal().server.pk, Mat(ctx().row_slots() + 1, 1)));
}

TEST(detects_nonzero_padding) {
    std::vector<std::int64_t> v(ctx().slots(), 0);
    v[0] = 1;
    v[3] = 9;
    he::EncMatrix m{2, 1, {encrypt_slots(keys_minimal(), v)}};
    CHECK_THROWS(he::decrypt_matrix(ctx(), keys_minimal().client.sk, m));
}

TEST(public_matmul_matches_field_reference) {
    Mat a = sample(6, 4, 1), b = sample(4, 3, 2);
    auto e = he::encrypt_matrix(ctx(), keys_minimal().server.pk, a);
    ctx().counts().reset();
    auto c = he::matmul_public(ctx(), e, b);
    CHECK(ctx().counts().mult_pt == 12 && ctx().counts().mult_ct == 0 && ctx().counts().rotate == 0);
    CHECK(he::decrypt_matrix(ctx(), keys_minimal().client.sk, c) == mat_mul(F(), a, b));
}

TEST(public_matmul_with_zero_and_negative_operands) {
    Mat a = sample(5, 3, 3);
    Mat b = Mat::from_ints(F(), {{0, -1}, {1, 0}, {-32768, 65536}});
    auto c = he::matmul_public(ctx(), he::encrypt_matrix(ctx(), keys_minimal().server.pk, a), b);
    CHECK(he::decrypt_matrix(ctx(), keys_minimal().client.sk, c) == mat_mul(F(), a, b));
}

TEST(encrypted_addition_and_offset_match_reference) {
    Mat a = sample(4, 3, 4), b = sample(4, 3, 5), c0 = sample(4, 3, 6);
    auto ea = he::encrypt_matrix(ctx(), keys_minimal().server.pk, a);
    auto eb = he::encrypt_matrix(ctx(), keys_minimal().server.pk, b);
    CHECK(he::decrypt_matrix(ctx(), keys_minimal().client.sk, he::add(ctx(), ea, eb)) == mat_add(F(), a, b));
    CHECK(he::decrypt_matrix(ctx(), keys_minimal().client.sk, he::add_plain(ctx(), ea, c0)) == mat_add(F(), a, c0));
}

TEST(encrypted_square_matches_reference) {
    Mat a = sample(5, 3, 7);
    auto e = he::encrypt_matrix(ctx(), keys_relin().server.pk, a);
    auto s = he::square(ctx(), e);
    CHECK(he::decrypt_matrix(ctx(), keys_relin().client.sk, s) == square(F(), a));
}

TEST(square_without_relin_key_is_refused_by_library) {
    auto e = he::encrypt_matrix(ctx(), keys_minimal().server.pk, sample(3, 1, 8));
    CHECK_THROWS(he::square(ctx(), e));
}

TEST(shape_mismatch_rejected) {
    auto e = he::encrypt_matrix(ctx(), keys_minimal().server.pk, sample(4, 3, 9));
    auto e2 = he::encrypt_matrix(ctx(), keys_minimal().server.pk, sample(4, 2, 10));
    CHECK_THROWS(he::matmul_public(ctx(), e, sample(2, 2, 11)));
    CHECK_THROWS(he::add(ctx(), e, e2));
    CHECK_THROWS(he::add_plain(ctx(), e, sample(3, 3, 12)));
    he::EncMatrix broken = e;
    broken.col.pop_back();
    CHECK_THROWS(he::matmul_public(ctx(), broken, sample(3, 2, 13)));
}

TEST(context_mismatch_rejected) {
    he::Context other = he::Context::create({65537, 1, 0});
    auto k = he::keygen(other, {"honest_minimal", false, {}});
    auto foreign = he::encrypt_matrix(other, k.server.pk, sample(4, 3, 14));
    auto local = he::encrypt_matrix(ctx(), keys_minimal().server.pk, sample(4, 3, 15));
    CHECK_THROWS(he::add(ctx(), local, foreign));
    CHECK_THROWS(he::matmul_public(ctx(), foreign, sample(3, 2, 16)));
    CHECK_THROWS(he::decrypt_matrix(ctx(), keys_minimal().client.sk, foreign));
}

TEST(dataseal_matmul_over_he_matches_plain_and_verifies) {
    OsRng os;
    Mat a = sample(6, 4, 17), b = sample(4, 3, 18);
    auto enc = matmul_encode(F(), a, b, matmul_keygen(F(), 6, os));
    auto ct = he::encrypt_matrix(ctx(), keys_minimal().server.pk, enc.server.a_star);
    CHECK(ct.rows == 8);
    Mat out = he::decrypt_matrix(ctx(), keys_minimal().client.sk, he::matmul_public(ctx(), ct, enc.server.b));
    CHECK(out == matmul_eval(F(), enc.server));
    for (auto mode : {MatmulVerifier::Original, MatmulVerifier::Strengthened, MatmulVerifier::Appendix})
        CHECK(matmul_verify(F(), enc.client, out, mode).accepted());
}

TEST(dataseal_addition_over_he_matches_plain_and_verifies) {
    OsRng os;
    Mat a = sample(5, 3, 19), b = sample(5, 3, 20);
    auto enc = add_encode(F(), a, b, add_keygen(F(), 5, os));
    auto ea = he::encrypt_matrix(ctx(), keys_minimal().server.pk, enc.server.a_star);
    auto eb = he::encrypt_matrix(ctx(), keys_minimal().server.pk, enc.server.b_star);
    Mat out = he::decrypt_matrix(ctx(), keys_minimal().client.sk, he::add(ctx(), ea, eb));
    CHECK(out == add_eval(F(), enc.server));
    CHECK(add_verify(F(), enc.client, out).accepted());
}

TEST(dataseal_square_over_he_matches_plain_and_verifies) {
    OsRng os;
    Mat a = sample(4, 3, 21);
    auto enc = square_encode(F(), a, square_keygen(F(), 3, os));
    auto ea = he::encrypt_matrix(ctx(), keys_relin().server.pk, enc.server.a_star);
    Mat out = he::decrypt_matrix(ctx(), keys_relin().client.sk, he::square(ctx(), ea));
    CHECK(out == square_eval(F(), enc.server));
    CHECK(square_verify(F(), enc.client, out).accepted());
}

TEST(sketch_data_only_encoding_and_composition) {
    OsRng os;
    const std::size_t n = 6;
    auto cs = sketch_keygen(F(), sketch_rows_for(F().p(), 128, 1ULL << 32), n, os);
    SketchServerView plain_sv;
    Mat a = sample(n, 4, 22), d = sample(n, 5, 23);
    sketch_register(F(), cs, plain_sv, "A", a);
    sketch_register(F(), cs, plain_sv, "D", d);
    std::map<std::string, he::EncMatrix> enc;
    for (const auto& [label, m] : plain_sv.inputs) enc[label] = he::encrypt_matrix(ctx(), keys_minimal().server.pk, m);
    for (const auto& [label, m] : enc) {
        CHECK(m.rows == n);
        for (const auto& c : m.col) {
            auto slots = he::decrypt_slots(ctx(), keys_minimal().client.sk, c);
            for (std::size_t i = n; i < slots.size(); ++i) CHECK(slots[i] == 0);
        }
    }
    Mat b1 = sample(4, 5, 24), b2 = sample(5, 3, 25), c0 = sample(n, 3, 26);
    Program p1 = (Program::input("A").mul_right(b1) + Program::input("D")).mul_right(b2);
    Program p2 = Program::input("A").mul_right(sample(4, 3, 27)) + Program::constant(c0);
    for (const Program* p : {&p1, &p2}) {
        Mat y = he::decrypt_matrix(ctx(), keys_minimal().client.sk, he::eval_program(ctx(), enc, *p));
        CHECK(y == sketch_eval(F(), plain_sv, *p));
        CHECK(sketch_verify(F(), cs, sketch_prepare(F(), cs, *p), y));
    }
    CHECK_THROWS(he::eval_program(ctx(), enc, Program::constant(c0)));
}

TEST_MAIN()
