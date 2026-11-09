#include <filesystem>
#include <fstream>
#include <iostream>
#include <sstream>

#include "dsf/dataseal.hpp"
#include "dsf/he.hpp"
#include "dsf/he_io.hpp"
#include "dsf/rng.hpp"
#include "dsf/sketch.hpp"

using namespace dsf;
namespace fs = std::filesystem;

namespace {

Mat sample(const Field& f, std::size_t r, std::size_t c, std::uint64_t seed) {
    SeededRng rng(seed);
    Mat m(r, c);
    for (std::size_t i = 0; i < r; ++i)
        for (std::size_t j = 0; j < c; ++j) m.at(i, j) = uniform_elem(f, rng);
    return m;
}

std::string counts_json(const he::OpCounts& c) {
    std::ostringstream os;
    os << "{\"encrypt\": " << c.encrypt << ", \"decrypt\": " << c.decrypt << ", \"add_ct\": " << c.add_ct
       << ", \"add_pt\": " << c.add_pt << ", \"mult_pt\": " << c.mult_pt << ", \"mult_ct\": " << c.mult_ct
       << ", \"rotate\": " << c.rotate << "}";
    return os.str();
}

struct Row {
    std::string workload;
    bool relin;
    std::size_t in_cts, out_cts, out_rows;
    he::OpCounts eval;
    bool exact;
    bool accepted;
};

}  // namespace

int main(int argc, char** argv) {
    if (argc != 2) {
        std::cerr << "usage: dsf_he_manifest <out_dir>\n";
        return 2;
    }
    fs::path out = argv[1];
    fs::create_directories(out);

    he::Context ctx = he::Context::create({});
    const Field& f = ctx.field();
    {
        std::ofstream os(out / "he_context.json");
        os << ctx.describe_json();
    }

    auto probe_keys = he::keygen(ctx, {"declared_extended", false, {1}});
    const std::size_t S = ctx.slots(), R = ctx.row_slots();
    std::vector<std::int64_t> v(S, 0);
    v[0] = 1;
    v[R] = 2;
    auto ct = ctx.cc()->Encrypt(probe_keys.server.pk, ctx.cc()->MakePackedPlaintext(v));
    auto same = he::decrypt_slots(ctx, probe_keys.client.sk, ct);
    auto rot = he::decrypt_slots(ctx, probe_keys.client.sk, ctx.cc()->EvalAtIndex(ct, 1));
    {
        std::ofstream os(out / "slot_probe.json");
        os << "{\n  \"slots\": " << S << ",\n  \"row_slots\": " << R << ",\n";
        os << "  \"identity_order\": " << (same[0] == 1 && same[R] == 2 ? "true" : "false") << ",\n";
        os << "  \"eval_at_index_1_moves_slot_0_to\": " << (rot[R - 1] == 1 ? std::to_string(R - 1) : "\"other\"") << ",\n";
        os << "  \"eval_at_index_1_moves_slot_R_to\": " << (rot[S - 1] == 2 ? std::to_string(S - 1) : "\"other\"") << ",\n";
        os << "  \"semantics\": \"out[i] = in[(i+1) mod R] within each row of R slots\"\n}\n";
    }

    OsRng os_rng;
    std::vector<Row> rows;
    const std::size_t n = 4, d = 3, ell = 2;

    {
        auto kp = he::keygen(ctx, {"honest_minimal", false, {}});
        auto enc = matmul_encode(f, sample(f, n, d, 1), sample(f, d, ell, 2), matmul_keygen(f, n, os_rng));
        auto in = he::encrypt_matrix(ctx, kp.server.pk, enc.server.a_star);
        ctx.counts().reset();
        auto res = he::matmul_public(ctx, in, enc.server.b);
        auto eval = ctx.counts();
        Mat o = he::decrypt_matrix(ctx, kp.client.sk, res);
        rows.push_back({"dataseal_matmul", false, in.col.size(), res.col.size(), res.rows, eval,
                        o == matmul_eval(f, enc.server), matmul_verify(f, enc.client, o, MatmulVerifier::Strengthened).accepted()});
    }
    {
        auto kp = he::keygen(ctx, {"honest_minimal", false, {}});
        auto enc = add_encode(f, sample(f, n, d, 3), sample(f, n, d, 4), add_keygen(f, n, os_rng));
        auto a = he::encrypt_matrix(ctx, kp.server.pk, enc.server.a_star);
        auto b = he::encrypt_matrix(ctx, kp.server.pk, enc.server.b_star);
        ctx.counts().reset();
        auto res = he::add(ctx, a, b);
        auto eval = ctx.counts();
        Mat o = he::decrypt_matrix(ctx, kp.client.sk, res);
        rows.push_back({"dataseal_add", false, a.col.size() + b.col.size(), res.col.size(), res.rows, eval,
                        o == add_eval(f, enc.server), add_verify(f, enc.client, o).accepted()});
    }
    {
        auto kp = he::keygen(ctx, {"honest_minimal", true, {}});
        auto enc = square_encode(f, sample(f, n, d, 5), square_keygen(f, d, os_rng));
        auto a = he::encrypt_matrix(ctx, kp.server.pk, enc.server.a_star);
        ctx.counts().reset();
        auto res = he::square(ctx, a);
        auto eval = ctx.counts();
        Mat o = he::decrypt_matrix(ctx, kp.client.sk, res);
        rows.push_back({"dataseal_square", true, a.col.size(), res.col.size(), res.rows, eval,
                        o == square_eval(f, enc.server), square_verify(f, enc.client, o).accepted()});
    }
    {
        auto kp = he::keygen(ctx, {"honest_minimal", false, {}});
        auto cs = sketch_keygen(f, sketch_rows_for(f.p(), 128, 1ULL << 32), n, os_rng);
        SketchServerView sv;
        sketch_register(f, cs, sv, "A", sample(f, n, d, 6));
        sketch_register(f, cs, sv, "D", sample(f, n, 5, 7));
        std::map<std::string, he::EncMatrix> enc;
        std::size_t in_cts = 0;
        for (const auto& [l, m] : sv.inputs) {
            enc[l] = he::encrypt_matrix(ctx, kp.server.pk, m);
            in_cts += enc[l].col.size();
        }
        Program p = (Program::input("A").mul_right(sample(f, d, 5, 8)) + Program::input("D")).mul_right(sample(f, 5, ell, 9));
        ctx.counts().reset();
        auto res = he::eval_program(ctx, enc, p);
        auto eval = ctx.counts();
        Mat o = he::decrypt_matrix(ctx, kp.client.sk, res);
        rows.push_back({"private_sketch_composition", false, in_cts, res.col.size(), res.rows, eval,
                        o == sketch_eval(f, sv, p), sketch_verify(f, cs, sketch_prepare(f, cs, p), o)});
    }

    std::size_t fresh_ct = he::serialized_bytes(ct);
    {
        std::ofstream os(out / "capabilities_honest_minimal.json");
        os << "{\n  \"profile\": \"honest_minimal\",\n  \"shape\": {\"n\": " << n << ", \"d\": " << d << ", \"ell\": " << ell
           << "},\n  \"layout\": \"column_packed_v1\",\n  \"fresh_ciphertext_bytes\": " << fresh_ct << ",\n  \"workloads\": [\n";
        for (std::size_t i = 0; i < rows.size(); ++i) {
            const Row& r = rows[i];
            os << "    {\"workload\": \"" << r.workload << "\", \"public_key\": true, \"relin_key\": " << (r.relin ? "true" : "false")
               << ", \"rotation_indices\": [], \"input_ciphertexts\": " << r.in_cts << ", \"output_ciphertexts\": " << r.out_cts
               << ", \"output_logical_rows\": " << r.out_rows << ", \"server_ops\": " << counts_json(r.eval)
               << ", \"exact_match\": " << (r.exact ? "true" : "false") << ", \"accepted\": " << (r.accepted ? "true" : "false")
               << "}" << (i + 1 < rows.size() ? "," : "") << "\n";
        }
        os << "  ]\n}\n";
    }
    bool ok = true;
    for (const auto& r : rows) ok = ok && r.exact && r.accepted;
    std::cout << "wrote " << out.string() << (ok ? " (all exact)" : " (MISMATCH)") << "\n";
    return ok ? 0 : 1;
}
