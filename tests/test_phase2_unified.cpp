#include "dsf/dataseal.hpp"
#include "dsf/he.hpp"
#include "dsf/he_rowmajor.hpp"
#include "dsf/rng.hpp"
#include "dsf/sketch.hpp"
#include "dsf/sketch_program.hpp"
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

he::RowCipher enc_row(const he::KeyPair& k, const Mat& m, std::size_t data_rows, std::size_t D) {
    return he::encrypt_rowmajor(ctx(), k.server.pk, m, he::make_layout(m.rows(), m.cols(), data_rows, D));
}

std::size_t sketch_rows() { return sketch_rows_for(F().p(), 128, 1ULL << 32); }

}  // namespace

// FHE-only, Original DataSeal, Strengthened DataSeal: one shared row-major
// public multiplication, identical encrypted evaluation; only the client-side
// verifier differs.
TEST(fhe_only_and_dataseal_share_one_evaluation) {
    OsRng os;
    std::size_t n = 4, d = 3, ell = 2;
    std::size_t D = he::padded_dim_for(n + 2, d, ell);
    Mat a = sample(n, d, 1), b = sample(d, ell, 2);

    // FHE-only: data matrix only.
    auto kf = he::keygen(ctx(), {"fhe_only", false, he::public_matmul_rotation_indices(d, ell)});
    auto efo = he::public_right_matmul(ctx(), enc_row(kf, a, n, D), b, ell);
    CHECK(he::decrypt_rowmajor(ctx(), kf.client.sk, efo) == mat_mul(F(), a, b));

    // Original / Strengthened: same encrypted inputs and same server op.
    auto enc = matmul_encode(F(), a, b, matmul_keygen(F(), n, os));
    auto kd = he::keygen(ctx(), {"dataseal", false, he::public_matmul_rotation_indices(d, ell)});
    auto server_out = he::public_right_matmul(ctx(), enc_row(kd, enc.server.a_star, n, D), b, ell);
    Mat out = he::decrypt_rowmajor(ctx(), kd.client.sk, server_out);
    CHECK(out.top_rows(n) == mat_mul(F(), a, b));
    CHECK(matmul_verify(F(), enc.client, out, MatmulVerifier::Original).accepted());
    CHECK(matmul_verify(F(), enc.client, out, MatmulVerifier::Strengthened).accepted());
}

TEST(private_sketch_row_major_single_right_mult) {
    OsRng os;
    std::size_t n = 5, d = 3, ell = 2, D = he::padded_dim_for(n, d, ell);
    auto cs = sketch_keygen(F(), sketch_rows(), n, os);
    SketchServerView sv;
    Mat a = sample(n, d, 3), b = sample(d, ell, 4);
    sketch_register(F(), cs, sv, "A", a);
    Program prog = Program::input("A").mul_right(b);
    auto k = he::keygen(ctx(), {"sketch", false, he::program_rotation_indices(prog)});
    std::map<std::string, he::RowCipher> inputs{{"A", enc_row(k, a, n, D)}};
    Mat y = he::decrypt_rowmajor(ctx(), k.client.sk, he::eval_program_rowmajor(ctx(), inputs, prog));
    CHECK(y == mat_mul(F(), a, b));
    CHECK(sketch_verify(F(), cs, sketch_prepare(F(), cs, prog), y));
}

TEST(private_sketch_row_major_composition) {
    OsRng os;
    std::size_t n = 6, d = 4, h = 5, ell = 3;
    std::size_t D = he::padded_dim_for(n, std::max(d, h), ell);
    auto cs = sketch_keygen(F(), sketch_rows(), n, os);
    SketchServerView sv;
    Mat a = sample(n, d, 5), dmat = sample(n, h, 6), b1 = sample(d, h, 7), b2 = sample(h, ell, 8);
    sketch_register(F(), cs, sv, "A", a);
    sketch_register(F(), cs, sv, "D", dmat);
    Program prog = (Program::input("A").mul_right(b1) + Program::input("D")).mul_right(b2);
    auto k = he::keygen(ctx(), {"sketch", false, he::program_rotation_indices(prog)});
    std::map<std::string, he::RowCipher> inputs{{"A", enc_row(k, a, n, D)}, {"D", enc_row(k, dmat, n, D)}};
    Mat y = he::decrypt_rowmajor(ctx(), k.client.sk, he::eval_program_rowmajor(ctx(), inputs, prog));
    CHECK(y == mat_mul(F(), mat_add(F(), mat_mul(F(), a, b1), dmat), b2));
    CHECK(sketch_verify(F(), cs, sketch_prepare(F(), cs, prog), y));
}

TEST(private_sketch_row_major_affine_offset) {
    OsRng os;
    std::size_t n = 4, d = 3, ell = 2, D = he::padded_dim_for(n, d, ell);
    auto cs = sketch_keygen(F(), sketch_rows(), n, os);
    SketchServerView sv;
    Mat a = sample(n, d, 9), c0 = sample(n, ell, 10), b = sample(d, ell, 11);
    sketch_register(F(), cs, sv, "A", a);
    Program prog = Program::input("A").mul_right(b) + Program::constant(c0);
    auto k = he::keygen(ctx(), {"sketch", false, he::program_rotation_indices(prog)});
    std::map<std::string, he::RowCipher> inputs{{"A", enc_row(k, a, n, D)}};
    Mat y = he::decrypt_rowmajor(ctx(), k.client.sk, he::eval_program_rowmajor(ctx(), inputs, prog));
    CHECK(y == mat_add(F(), mat_mul(F(), a, b), c0));
    CHECK(sketch_verify(F(), cs, sketch_prepare(F(), cs, prog), y));
}

TEST(private_sketch_two_programs_from_one_encoding_row_major) {
    OsRng os;
    std::size_t n = 5, d = 4, D = 6;
    auto cs = sketch_keygen(F(), sketch_rows(), n, os);
    SketchServerView sv;
    Mat a = sample(n, d, 12);
    sketch_register(F(), cs, sv, "A", a);
    Mat b1 = sample(d, 3, 13), b2 = sample(d, 2, 14);
    Program p1 = Program::input("A").mul_right(b1);
    Program p2 = Program::input("A").mul_right(b2);
    std::vector<std::int32_t> rots = he::program_rotation_indices(p1);
    for (auto r : he::program_rotation_indices(p2)) rots.push_back(r);
    auto k = he::keygen(ctx(), {"sketch", false, rots});
    he::RowCipher ea = enc_row(k, a, n, D);
    std::map<std::string, he::RowCipher> inputs{{"A", ea}};
    Mat y1 = he::decrypt_rowmajor(ctx(), k.client.sk, he::eval_program_rowmajor(ctx(), inputs, p1));
    Mat y2 = he::decrypt_rowmajor(ctx(), k.client.sk, he::eval_program_rowmajor(ctx(), inputs, p2));
    CHECK(sketch_verify(F(), cs, sketch_prepare(F(), cs, p1), y1));
    CHECK(sketch_verify(F(), cs, sketch_prepare(F(), cs, p2), y2));
    CHECK(!sketch_verify(F(), cs, sketch_prepare(F(), cs, p1), y2));
}

TEST(square_fhe_only_and_dataseal_corrected_verifier) {
    OsRng os;
    std::size_t n = 4, d = 3, D = he::padded_dim_for(n + 1, d, 1);
    auto k = he::keygen(ctx(), {"square", true, {}});
    Mat a = sample(n, d, 15);
    // FHE-only square.
    auto efo = he::square_rowmajor(ctx(), enc_row(k, a, n, D));
    CHECK(he::decrypt_rowmajor(ctx(), k.client.sk, efo).top_rows(n) == square(F(), a));
    // Original DataSeal square with corrected verifier.
    auto enc = square_encode(F(), a, square_keygen(F(), d, os));
    auto out = he::decrypt_rowmajor(ctx(), k.client.sk, he::square_rowmajor(ctx(), enc_row(k, enc.server.a_star, n, D)));
    CHECK(out == square_eval(F(), enc.server));
    CHECK(square_verify(F(), enc.client, out).accepted());
}

TEST_MAIN()
