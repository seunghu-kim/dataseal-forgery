#include <chrono>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <sstream>

#include "dsf/dataseal.hpp"
#include "dsf/he.hpp"
#include "dsf/he_io.hpp"
#include "dsf/he_rowmajor.hpp"
#include "dsf/rng.hpp"

using namespace dsf;
namespace fs = std::filesystem;
using Clock = std::chrono::steady_clock;

namespace {

Mat sample(const Field& f, std::size_t r, std::size_t c, std::uint64_t seed) {
    SeededRng rng(seed);
    Mat m(r, c);
    for (std::size_t i = 0; i < r; ++i)
        for (std::size_t j = 0; j < c; ++j) m.at(i, j) = uniform_elem(f, rng);
    return m;
}

double ms_since(Clock::time_point t0) {
    return std::chrono::duration<double, std::milli>(Clock::now() - t0).count();
}

std::size_t towers(const he::Ct& ct) { return ct->GetElements()[0].GetNumOfElements(); }

std::string counts_json(const he::OpCounts& c) {
    std::ostringstream os;
    os << "{\"mult_ct\": " << c.mult_ct << ", \"mult_pt\": " << c.mult_pt << ", \"add_ct\": " << c.add_ct
       << ", \"rotate\": " << c.rotate << "}";
    return os.str();
}

}  // namespace

int main(int argc, char** argv) {
    if (argc != 2) {
        std::cerr << "usage: dsf_rowmajor_manifest <out_dir>\n";
        return 2;
    }
    fs::path out = argv[1];
    fs::create_directories(out);

    he::Context ctx = he::Context::create({65537, 3, 0});
    const Field& f = ctx.field();
    {
        std::ofstream os(out / "rowmajor_context.json");
        os << ctx.describe_json();
    }

    OsRng os_rng;
    std::ofstream os(out / "rowmajor_matmul.json");
    os << "{\n  \"layout\": \"row_major_jiang_2018_1041\",\n  \"note\": \"cyclic rotation is realized modulo n=D*D"
          " with two masked EvalAtIndex calls per diagonal, since OpenFHE BGV rotation is cyclic within a slot block\",\n"
          "  \"cases\": [\n";

    struct Case {
        std::size_t n, d, ell;
    };
    std::vector<Case> cases{{2, 2, 2}, {3, 3, 3}, {4, 3, 2}, {6, 5, 4}};
    bool all_ok = true;

    for (std::size_t ci = 0; ci < cases.size(); ++ci) {
        const auto& c = cases[ci];
        std::size_t D = he::padded_dim_for(c.n + 2, c.d, c.ell);
        auto rots = he::matmul_rotation_indices(D);

        auto t_key = Clock::now();
        auto kp = he::keygen(ctx, {"declared_extended", true, rots});
        double key_ms = ms_since(t_key);

        auto enc = matmul_encode(f, sample(f, c.n, c.d, 10 + ci), sample(f, c.d, c.ell, 20 + ci),
                                 matmul_keygen(f, c.n, os_rng));
        auto a_star = he::encrypt_rowmajor(ctx, kp.server.pk, enc.server.a_star, he::make_layout(c.n + 2, c.d, c.n, D));
        auto b = he::encrypt_rowmajor(ctx, kp.server.pk, enc.server.b, he::make_layout(c.d, c.ell, c.d, D));

        std::size_t level_before = a_star.ct->GetLevel(), towers_before = towers(a_star.ct);
        ctx.counts().reset();
        auto t_eval = Clock::now();
        he::RowCipher prod = he::matmul_augmented(ctx, a_star, b, c.ell);
        double eval_ms = ms_since(t_eval);
        auto eval_counts = ctx.counts();
        std::size_t level_after = prod.ct->GetLevel(), towers_after = towers(prod.ct);

        Mat result = he::decrypt_rowmajor(ctx, kp.client.sk, prod);
        bool exact = result == matmul_eval(f, enc.server);
        bool accepted = matmul_verify(f, enc.client, result, MatmulVerifier::Strengthened).accepted();
        all_ok = all_ok && exact && accepted;

        os << "    {\"n\": " << c.n << ", \"d\": " << c.d << ", \"ell\": " << c.ell << ", \"padded_dim\": " << D
           << ", \"rotation_keys\": " << rots.size() << ", \"relin_key\": true,\n"
           << "     \"level_before\": " << level_before << ", \"level_after\": " << level_after
           << ", \"towers_before\": " << towers_before << ", \"towers_after\": " << towers_after
           << ", \"levels_consumed\": " << (level_after - level_before) << ",\n"
           << "     \"server_ops\": " << counts_json(eval_counts) << ",\n"
           << "     \"input_ct_bytes\": " << he::serialized_bytes(a_star.ct)
           << ", \"output_ct_bytes\": " << he::serialized_bytes(prod.ct) << ",\n"
           << "     \"keygen_ms\": " << key_ms << ", \"eval_ms\": " << eval_ms
           << ", \"exact_match\": " << (exact ? "true" : "false") << ", \"accepted\": " << (accepted ? "true" : "false")
           << "}" << (ci + 1 < cases.size() ? "," : "") << "\n";

        he::clear_eval_keys();
    }
    os << "  ]\n}\n";
    std::cout << "wrote " << out.string() << (all_ok ? " (all exact)" : " (MISMATCH)") << "\n";
    return all_ok ? 0 : 1;
}
