#include <algorithm>
#include <chrono>
#include <cmath>
#include <filesystem>
#include <fstream>
#include <functional>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

#include "ciphertext-ser.h"
#include "cryptocontext-ser.h"
#include "key/key-ser.h"
#include "scheme/bgvrns/bgvrns-ser.h"

#include "dsf/dataseal.hpp"
#include "dsf/he.hpp"
#include "dsf/he_io.hpp"
#include "dsf/he_rowmajor.hpp"
#include "dsf/rng.hpp"
#include "dsf/sketch.hpp"

using namespace dsf;
namespace fs = std::filesystem;
using Clock = std::chrono::steady_clock;

namespace {

double ms(const std::function<void()>& body) {
    auto t0 = Clock::now();
    body();
    return std::chrono::duration<double, std::milli>(Clock::now() - t0).count();
}

struct Stat {
    double median = 0, stdev = 0;
    std::vector<double> raw;
};

Stat measure(std::size_t warmup, std::size_t trials, const std::function<void()>& body) {
    for (std::size_t i = 0; i < warmup; ++i) body();
    Stat s;
    for (std::size_t i = 0; i < trials; ++i) s.raw.push_back(ms(body));
    std::vector<double> v = s.raw;
    std::sort(v.begin(), v.end());
    s.median = v[v.size() / 2];
    double mean = 0;
    for (double x : v) mean += x;
    mean /= v.size();
    double var = 0;
    for (double x : v) var += (x - mean) * (x - mean);
    s.stdev = std::sqrt(var / v.size());
    return s;
}

Mat sample(const Field& f, std::size_t r, std::size_t c, std::uint64_t seed) {
    SeededRng rng(seed);
    Mat m(r, c);
    for (std::size_t i = 0; i < r; ++i)
        for (std::size_t j = 0; j < c; ++j) m.at(i, j) = uniform_elem(f, rng);
    return m;
}

std::size_t rotation_key_bytes(const he::Context& ctx) {
    std::stringstream ss;
    if (!lbcrypto::CryptoContextImpl<lbcrypto::DCRTPoly>::SerializeEvalAutomorphismKey(ss, lbcrypto::SerType::BINARY,
                                                                                      ctx.cc()))
        return 0;
    return ss.str().size();
}

std::string stat_json(const std::string& name, const Stat& s) {
    std::ostringstream os;
    os << "\"" << name << "\": {\"median_ms\": " << s.median << ", \"stdev_ms\": " << s.stdev << "}";
    return os.str();
}

struct Config {
    std::string name;
    std::size_t logical_rows;  // including checksum rows
    bool needs_relin = false;
};

// One matmul workload (n x d) * (d x ell), B public, in row-major packing.
struct Workload {
    std::size_t n, d, ell;
    std::size_t native_dim(std::size_t extra_rows) const {
        return he::padded_dim_for(n + extra_rows, d, ell);
    }
};

const std::size_t WARMUP = 2, TRIALS = 10;

std::string run_config(const he::Context& ctx, const Workload& w, const std::string& config, std::size_t D) {
    const Field& f = ctx.field();
    OsRng os;
    Mat A = sample(f, w.n, w.d, 1), B = sample(f, w.d, w.ell, 2);

    Stat client_prep, expected_prep, encrypt, server, decrypt, verify;
    std::size_t input_bytes = 0, output_bytes = 0, key_bytes = 0, levels = 0;
    he::OpCounts counts;
    std::string note = "";
    bool accepted = true, exact = true;

    double plain = measure(WARMUP, TRIALS, [&]() { volatile auto c = mat_mul(f, A, B); (void)c; }).median;

    if (config == "plaintext") {
        std::ostringstream os2;
        os2 << "    {\"config\": \"plaintext\", \"direct_plaintext_ms\": " << plain << "}";
        return os2.str();
    }

    if (config == "private_sketch") {
        auto cs = sketch_keygen(f, sketch_rows_for(f.p(), 128, 1ULL << 32), w.n, os);
        SketchServerView sv;
        // one-time registration (K A) measured separately from per-program work
        client_prep = measure(WARMUP, TRIALS, [&]() {
            SketchClientState tmp = cs;
            SketchServerView tsv;
            sketch_register(f, tmp, tsv, "A", A);
        });
        sketch_register(f, cs, sv, "A", A);
        Program prog = Program::input("A").mul_right(B);
        auto rots = he::program_rotation_indices(prog);
        auto kp = he::keygen(ctx, {"sketch", false, rots});
        key_bytes = rotation_key_bytes(ctx);
        he::RowCipher ea;
        encrypt = measure(WARMUP, TRIALS, [&]() {
            ea = he::encrypt_rowmajor(ctx, kp.server.pk, A, he::make_layout(w.n, w.d, w.n, D));
        });
        input_bytes = he::serialized_bytes(ea.ct);
        Mat tp;
        expected_prep = measure(WARMUP, TRIALS, [&]() { tp = sketch_prepare(f, cs, prog); });
        std::map<std::string, he::RowCipher> in{{"A", ea}};
        he::RowCipher y;
        ctx.counts().reset();
        server = measure(WARMUP, TRIALS, [&]() { y = he::eval_program_rowmajor(ctx, in, prog); });
        counts = ctx.counts();
        output_bytes = he::serialized_bytes(y.ct);
        levels = y.ct->GetLevel();
        Mat out;
        decrypt = measure(WARMUP, TRIALS, [&]() { out = he::decrypt_rowmajor(ctx, kp.client.sk, y); });
        verify = measure(WARMUP, TRIALS, [&]() { accepted = sketch_verify(f, cs, tp, out); });
        exact = out == mat_mul(f, A, B);
        note = "client_prep is one-time registration K*A; expected_prep and later are per-program";
    } else {
        // fhe_only, dataseal_original, dataseal_strengthened
        std::size_t extra = config == "fhe_only" ? 0 : 2;
        Mat encoded = A;
        MatmulClientState client;
        if (config != "fhe_only") {
            auto e = matmul_encode(f, A, B, matmul_keygen(f, w.n, os));
            client = e.client;
            encoded = e.server.a_star;
            client_prep = measure(WARMUP, TRIALS, [&]() {
                volatile auto tmp = matmul_encode(f, A, B, client.key);
                (void)tmp;
            });
            expected_prep = measure(WARMUP, TRIALS, [&]() { volatile auto z = client.z; (void)z; });
        }
        auto kp = he::keygen(ctx, {"dataseal", false, he::public_matmul_rotation_indices(w.d, w.ell)});
        key_bytes = rotation_key_bytes(ctx);
        he::RowCipher ea;
        encrypt = measure(WARMUP, TRIALS, [&]() {
            ea = he::encrypt_rowmajor(ctx, kp.server.pk, encoded, he::make_layout(w.n + extra, w.d, w.n, D));
        });
        input_bytes = he::serialized_bytes(ea.ct);
        he::RowCipher c;
        ctx.counts().reset();
        server = measure(WARMUP, TRIALS, [&]() { c = he::public_right_matmul(ctx, ea, B, w.ell); });
        counts = ctx.counts();
        output_bytes = he::serialized_bytes(c.ct);
        levels = c.ct->GetLevel();
        Mat out;
        decrypt = measure(WARMUP, TRIALS, [&]() { out = he::decrypt_rowmajor(ctx, kp.client.sk, c); });
        if (config == "fhe_only") {
            exact = out.top_rows(w.n) == mat_mul(f, A, B);
            verify.median = 0;
            accepted = exact;
        } else {
            MatmulVerifier mode = config == "dataseal_strengthened" ? MatmulVerifier::Strengthened
                                                                    : MatmulVerifier::Original;
            verify = measure(WARMUP, TRIALS, [&]() { accepted = matmul_verify(f, client, out, mode).accepted(); });
            exact = out.top_rows(w.n) == mat_mul(f, A, B);
        }
    }

    std::ostringstream os2;
    os2 << "    {\"config\": \"" << config << "\", \"padded_dim\": " << D << ", \"exact_match\": "
        << (exact ? "true" : "false") << ", \"accepted\": " << (accepted ? "true" : "false") << ",\n"
        << "     \"direct_plaintext_ms\": " << plain << ", " << stat_json("client_prep", client_prep) << ", "
        << stat_json("expected_prep", expected_prep) << ",\n     " << stat_json("encrypt", encrypt) << ", "
        << stat_json("server_eval", server) << ", " << stat_json("decrypt", decrypt) << ", "
        << stat_json("verify", verify) << ",\n"
        << "     \"input_ct_bytes\": " << input_bytes << ", \"output_ct_bytes\": " << output_bytes
        << ", \"rotation_key_bytes\": " << key_bytes << ", \"output_level\": " << levels << ",\n"
        << "     \"server_ops\": {\"mult_pt\": " << counts.mult_pt << ", \"mult_ct\": " << counts.mult_ct
        << ", \"add_ct\": " << counts.add_ct << ", \"rotate\": " << counts.rotate << "}";
    if (!note.empty()) os2 << ",\n     \"note\": \"" << note << "\"";
    os2 << "}";
    return os2.str();
}

}  // namespace

int main(int argc, char** argv) {
    if (argc != 2) {
        std::cerr << "usage: dsf_phase2_bench <out_dir>\n";
        return 2;
    }
    fs::path out = argv[1];
    fs::create_directories(out);
    he::Context ctx = he::Context::create({65537, 2, 0});
    {
        std::ofstream os(out / "phase2_context.json");
        os << ctx.describe_json();
    }

    std::vector<Workload> workloads{{4, 4, 4}, {8, 8, 8}, {16, 16, 16}, {8, 4, 6}};
    std::vector<std::string> configs{"plaintext", "fhe_only", "dataseal_original", "dataseal_strengthened",
                                     "private_sketch"};

    for (const std::string& group : {"controlled", "native"}) {
        std::ofstream os(out / ("phase2_matmul_" + group + ".json"));
        os << "{\n  \"group\": \"" << group << "\",\n  \"packing\": \"row_major\",\n"
           << "  \"warmup\": " << WARMUP << ", \"trials\": " << TRIALS << ",\n  \"workloads\": [\n";
        for (std::size_t wi = 0; wi < workloads.size(); ++wi) {
            const Workload& w = workloads[wi];
            std::size_t controlled_D = he::padded_dim_for(w.n + 2, w.d, w.ell);
            os << "    {\"n\": " << w.n << ", \"d\": " << w.d << ", \"ell\": " << w.ell << ", \"results\": [\n";
            for (std::size_t ci = 0; ci < configs.size(); ++ci) {
                std::size_t extra = (configs[ci] == "dataseal_original" || configs[ci] == "dataseal_strengthened") ? 2 : 0;
                std::size_t D = group == "controlled" ? controlled_D : w.native_dim(extra);
                os << run_config(ctx, w, configs[ci], D) << (ci + 1 < configs.size() ? "," : "") << "\n";
            }
            os << "    ]}" << (wi + 1 < workloads.size() ? "," : "") << "\n";
        }
        os << "  ]\n}\n";
        std::cout << "wrote " << (out / ("phase2_matmul_" + group + ".json")).string() << "\n";
    }
    return 0;
}
