#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

#include "dsf/dataseal.hpp"
#include "dsf/he.hpp"
#include "dsf/he_attacks.hpp"
#include "dsf/he_io.hpp"
#include "dsf/he_rowmajor.hpp"
#include "dsf/judge.hpp"
#include "dsf/rng.hpp"

using namespace dsf;
namespace fs = std::filesystem;

namespace {

struct Row {
    std::string attack, operation, verifier;
    bool accepted = false, wrong = false, unchanged = false, forged = false, supported = true;
    std::size_t rotations_used = 0;
};

std::string esc(const std::string& s) { return s; }

void emit(std::ostream& os, const Row& r, bool last) {
    os << "    {\"attack\": \"" << esc(r.attack) << "\", \"operation\": \"" << esc(r.operation)
       << "\", \"verifier\": \"" << esc(r.verifier) << "\", \"supported\": " << (r.supported ? "true" : "false")
       << ", \"accepted\": " << (r.accepted ? "true" : "false") << ", \"wrong_output\": " << (r.wrong ? "true" : "false")
       << ", \"unchanged\": " << (r.unchanged ? "true" : "false") << ", \"forged\": " << (r.forged ? "true" : "false")
       << ", \"rotations_used\": " << r.rotations_used << "}" << (last ? "" : ",") << "\n";
}

}  // namespace

int main(int argc, char** argv) {
    if (argc < 2) {
        std::cerr << "usage: dsf_attack_runner <out_dir> [attack_worker_path]\n";
        return 2;
    }
    fs::path out = argv[1];
    fs::create_directories(out);
    const std::string worker = argc >= 3 ? argv[2] : "";

    he::Context ctx = he::Context::create({65537, 5, 0});
    const Field& f = ctx.field();
    const std::size_t N = 3, D = 5;
    auto caps = he::Capabilities{"declared_extended_jiang", true, he::matmul_rotation_indices(D)};
    auto kp = he::keygen(ctx, caps);

    auto enc_row = [&](const Mat& m, std::size_t data_rows) {
        return he::encrypt_rowmajor(ctx, kp.server.pk, m, he::make_layout(m.rows(), m.cols(), data_rows, D));
    };

    Mat A = Mat::from_ints(f, {{1, 0}, {2, 1}, {0, 1}});
    Mat B = Mat::from_ints(f, {{1, 2}, {3, 4}});
    Vec k = vec_from_ints(f, {2, 3, 5});
    std::vector<Row> rows;

    // Linear: encrypted kernel on matmul (original, strengthened, appendix).
    {
        auto e = matmul_encode(f, A, B, {k, 7});
        auto in = enc_row(e.server.a_star, N);
        auto rhs = enc_row(e.server.b, B.rows());
        auto honest = he::matmul_augmented(ctx, in, rhs, B.cols());
        he::RotationAudit audit;
        auto changed = he::kernel_adjusted_output(ctx, in, honest, caps, N, {0, 1, 0}, &audit);
        Mat c0 = he::decrypt_rowmajor(ctx, kp.client.sk, honest);
        Mat c1 = he::decrypt_rowmajor(ctx, kp.client.sk, changed);
        Mat correct = mat_mul(f, A, B);
        for (auto mode : {MatmulVerifier::Original, MatmulVerifier::Strengthened, MatmulVerifier::Appendix}) {
            Attempt a = judge(matmul_verify(f, e.client, c1, mode).accepted(), c1, c0, c1.top_rows(N), correct);
            rows.push_back({"encrypted_kernel", "matmul", to_string(mode), a.accepted, a.wrong_output, a.unchanged,
                            a.forged(), true, audit.used.size()});
        }
    }
    // Linear: selective scaling on matmul.
    {
        auto e = matmul_encode(f, A, B, {k, 7});
        auto in = enc_row(e.server.a_star, N);
        auto rhs = enc_row(e.server.b, B.rows());
        auto honest = he::matmul_augmented(ctx, in, rhs, B.cols());
        auto changed = he::selective_scaling(ctx, honest, N, 3);
        Mat c0 = he::decrypt_rowmajor(ctx, kp.client.sk, honest);
        Mat c1 = he::decrypt_rowmajor(ctx, kp.client.sk, changed);
        Mat correct = mat_mul(f, A, B);
        for (auto mode : {MatmulVerifier::Original, MatmulVerifier::Strengthened}) {
            Attempt a = judge(matmul_verify(f, e.client, c1, mode).accepted(), c1, c0, c1.top_rows(N), correct);
            rows.push_back({"selective_scaling", "matmul", to_string(mode), a.accepted, a.wrong_output, a.unchanged,
                            a.forged(), true, 0});
        }
    }
    // Linear: encrypted kernel on addition.
    {
        Mat b2 = Mat::from_ints(f, {{4, 1}, {0, 9}, {2, 2}});
        auto e = add_encode(f, A, b2, k);
        auto in = enc_row(e.server.a_star, N);
        auto other = enc_row(e.server.b_star, N);
        auto honest = he::add_rowmajor(ctx, in, other);
        he::RotationAudit audit;
        auto changed = he::kernel_adjusted_output(ctx, in, honest, caps, N, {0, 1, 1}, &audit);
        Mat c0 = he::decrypt_rowmajor(ctx, kp.client.sk, honest);
        Mat c1 = he::decrypt_rowmajor(ctx, kp.client.sk, changed);
        Attempt a = judge(add_verify(f, e.client, c1).accepted(), c1, c0, c1.top_rows(N), mat_add(f, A, b2));
        rows.push_back({"encrypted_kernel", "addition", "addition", a.accepted, a.wrong_output, a.unchanged, a.forged(),
                        true, audit.used.size()});
    }
    // Squaring: permutation, rescaling, zero-product.
    {
        Mat sa = Mat::from_ints(f, {{2, 3}, {4, 5}, {6, 7}});
        auto e = square_encode(f, sa, vec_from_ints(f, {7, 11}));
        auto in = enc_row(e.server.a_star, N);
        auto honest = he::square_rowmajor(ctx, in);
        Mat c0 = he::decrypt_rowmajor(ctx, kp.client.sk, honest);
        Mat correct = square(f, sa);
        he::RotationAudit audit;
        auto perm = he::square_permute(ctx, honest, caps, N, 0, 2, 1, &audit);
        Mat cp = he::decrypt_rowmajor(ctx, kp.client.sk, perm);
        Attempt ap = judge(square_verify(f, e.client, cp).accepted(), cp, c0, cp.top_rows(N), correct);
        rows.push_back({"column_permutation", "square", "square", ap.accepted, ap.wrong_output, ap.unchanged,
                        ap.forged(), true, audit.used.size()});
        auto resc = he::square_rescale(ctx, honest, N, 1, 0, 2, 3);
        Mat cr = he::decrypt_rowmajor(ctx, kp.client.sk, resc);
        Attempt ar = judge(square_verify(f, e.client, cr).accepted(), cr, c0, cr.top_rows(N), correct);
        rows.push_back({"compensating_rescale", "square", "square", ar.accepted, ar.wrong_output, ar.unchanged,
                        ar.forged(), true, 0});
    }
    {
        Mat sa = Mat::from_ints(f, {{0, 2}, {3, 4}, {5, 6}});
        auto e = square_encode(f, sa, vec_from_ints(f, {7, 11}));
        auto in = enc_row(e.server.a_star, N);
        auto honest = he::square_rowmajor(ctx, in);
        Mat c0 = he::decrypt_rowmajor(ctx, kp.client.sk, honest);
        auto zc = he::square_zero_column(ctx, honest, N, 0);
        Mat cz = he::decrypt_rowmajor(ctx, kp.client.sk, zc);
        Attempt az = judge(square_verify(f, e.client, cz).accepted(), cz, c0, cz.top_rows(N), square(f, sa));
        rows.push_back({"conditional_zero_product", "square", "square", az.accepted, az.wrong_output, az.unchanged,
                        az.forged(), true, 0});
    }

    {
        std::ofstream os(out / "attacks.json");
        os << "{\n  \"context\": \"row_major_jiang, depth 5\",\n  \"capability_profile\": \"declared_extended_jiang\",\n"
           << "  \"note\": \"forged = accepted AND wrong_output; counted only on real ciphertext results\",\n"
           << "  \"results\": [\n";
        for (std::size_t i = 0; i < rows.size(); ++i) emit(os, rows[i], i + 1 == rows.size());
        os << "  ]\n}\n";
    }
    {
        std::ofstream os(out / "capabilities_declared_extended.json");
        auto rots = he::matmul_rotation_indices(D);
        os << "{\n  \"profile\": \"declared_extended_jiang\",\n  \"public_key\": true,\n  \"relin_key\": true,\n"
           << "  \"rotation_index_count\": " << rots.size() << ",\n  \"rotation_indices\": [";
        for (std::size_t i = 0; i < rots.size(); ++i) os << (i ? ", " : "") << rots[i];
        os << "],\n  \"padded_dim\": " << D << ",\n"
           << "  \"note\": \"these keys are exactly matmul_rotation_indices(D) plus a relinearization key; the "
              "column-packed honest_minimal profile has none of them\"\n}\n";
    }

    // Separate-process demonstration for the kernel matmul attack.
    bool worker_ok = false, worker_forged = false, bundle_clean = false;
    if (!worker.empty()) {
        std::string root = (out / "worker_demo").string();
        fs::remove_all(root);
        std::string bundle = root + "/server";
        std::string wout = root + "/out";
        fs::create_directories(wout);

        auto e = matmul_encode(f, A, B, {k, 7});
        auto in = enc_row(e.server.a_star, N);
        auto rhs = enc_row(e.server.b, B.rows());
        auto honest = he::matmul_augmented(ctx, in, rhs, B.cols());
        he::write_server_bundle(bundle, ctx, kp.server, {}, {});
        he::write_rowcipher(bundle, "input", in);
        he::write_rowcipher(bundle, "honest", honest);
        {
            std::ofstream pf(bundle + "/attack_params.txt");
            pf << N << " 0 1 0\n";
        }
        std::string cmd = worker + " " + bundle + " " + wout + " >/dev/null 2>&1";
        worker_ok = std::system(cmd.c_str()) == 0;

        std::string sk_bytes = he::serialize_secret_key(kp.client.sk);
        std::string probe = sk_bytes.substr(sk_bytes.size() / 2, 64);
        bundle_clean = true;
        for (const auto& name : he::list_files(bundle))
            if (he::read_file((fs::path(bundle) / name).string()).find(probe) != std::string::npos) bundle_clean = false;

        if (worker_ok) {
            he::RowCipher forged = he::read_rowcipher(wout, "forged");
            Mat c1 = he::decrypt_rowmajor(ctx, kp.client.sk, forged);
            Mat expected = attack_kernel(f, e.server.a_star, matmul_eval(f, e.server), N, {0, 1, 0});
            worker_forged = c1 == expected &&
                            matmul_verify(f, e.client, c1, MatmulVerifier::Strengthened).accepted() &&
                            c1.top_rows(N) != mat_mul(f, A, B);
        }
        std::ofstream os(out / "separate_process_demo.json");
        os << "{\n  \"attack\": \"encrypted_kernel matmul\",\n  \"worker_input\": \"public bundle directory only\",\n"
           << "  \"worker_exit_ok\": " << (worker_ok ? "true" : "false")
           << ",\n  \"bundle_has_no_secret\": " << (bundle_clean ? "true" : "false")
           << ",\n  \"result_is_forged_and_accepted\": " << (worker_forged ? "true" : "false") << "\n}\n";
    }

    std::size_t forged_count = 0;
    for (const auto& r : rows) forged_count += r.forged ? 1 : 0;
    bool ok = forged_count >= 6 && (worker.empty() || (worker_ok && worker_forged && bundle_clean));
    std::cout << "wrote " << out.string() << "; forged " << forged_count << "/" << rows.size()
              << (worker.empty() ? "" : (ok ? "; worker demo ok" : "; worker demo FAILED")) << "\n";
    return ok ? 0 : 1;
}
