#include <algorithm>
#include <chrono>
#include <cmath>
#include <filesystem>
#include <fstream>
#include <functional>
#include <iostream>
#include <sstream>
#include <vector>

#include "dsf/dataseal.hpp"
#include "dsf/matrix.hpp"
#include "dsf/rng.hpp"
#include "dsf/sketch.hpp"

using namespace dsf;
using Clock = std::chrono::steady_clock;

namespace {

double median_ms(std::size_t warmup, std::size_t trials, const std::function<void()>& body) {
    for (std::size_t i = 0; i < warmup; ++i) body();
    std::vector<double> v;
    for (std::size_t i = 0; i < trials; ++i) {
        auto t0 = Clock::now();
        body();
        v.push_back(std::chrono::duration<double, std::milli>(Clock::now() - t0).count());
    }
    std::sort(v.begin(), v.end());
    return v[v.size() / 2];
}

Mat sample(const Field& f, std::size_t r, std::size_t c, std::uint64_t seed) {
    SeededRng rng(seed);
    Mat m(r, c);
    for (std::size_t i = 0; i < r; ++i)
        for (std::size_t j = 0; j < c; ++j) m.at(i, j) = uniform_elem(f, rng);
    return m;
}

}  // namespace

int main(int argc, char** argv) {
    if (argc != 2) {
        std::cerr << "usage: dsf_phase2_audit <out_dir>\n";
        return 2;
    }
    std::filesystem::path out = argv[1];
    std::filesystem::create_directories(out);
    const Field f(65537);
    OsRng os;
    const std::size_t WARM = 20, TRIALS = 200;
    const std::size_t n = 16, ell = 16;

    Mat A = sample(f, n, 16, 1), B = sample(f, 16, ell, 2);
    Mat C = mat_mul(f, A, B);

    // DataSeal matmul verify: single weighted-checksum row k (1 x n).
    auto enc = matmul_encode(f, A, B, matmul_keygen(f, n, os));
    Mat c_star(n + 2, ell);
    for (std::size_t i = 0; i < n; ++i)
        for (std::size_t j = 0; j < ell; ++j) c_star.at(i, j) = C.at(i, j);
    c_star.set_row(n, enc.client.u0);
    c_star.set_row(n + 1, enc.client.z);
    double ds_verify = median_ms(WARM, TRIALS, [&]() {
        volatile bool ok = matmul_verify(f, enc.client, c_star, MatmulVerifier::Strengthened).accepted();
        (void)ok;
    });

    // Private sketch verify K Y = T_P for varying number of verification rows r.
    std::ostringstream os2;
    os2 << "{\n  \"workload\": {\"n\": " << n << ", \"ell\": " << ell << "},\n"
        << "  \"dataseal_strengthened_verify_rows\": 1,\n"
        << "  \"dataseal_strengthened_verify_ms\": " << ds_verify << ",\n"
        << "  \"note\": \"DataSeal applies one weighted-checksum vector k (1 x n); private-sketch applies K (r x n), so"
           " verify is O(r n ell) vs O(n ell). Padding D does not enter: verify runs on the decrypted logical n x ell"
           " matrix, independent of row-major padded dimension.\",\n"
        << "  \"private_sketch\": [\n";
    std::vector<std::size_t> rs{1, 2, 5, 8, 10, 16, 20, 32};
    for (std::size_t idx = 0; idx < rs.size(); ++idx) {
        std::size_t r = rs[idx];
        SketchClientState cs;
        cs.k = sample(f, r, n, 100 + r);
        SketchServerView sv;
        sketch_register(f, cs, sv, "A", A);
        Program prog = Program::input("A").mul_right(B);
        Mat tp = sketch_prepare(f, cs, prog);
        double v = median_ms(WARM, TRIALS, [&]() {
            volatile bool ok = sketch_verify(f, cs, tp, C);
            (void)ok;
        });
        double per_row = v / static_cast<double>(r);
        os2 << "    {\"verify_rows_r\": " << r << ", \"verify_ms\": " << v << ", \"verify_ms_per_row\": " << per_row
            << ", \"ratio_to_dataseal\": " << (v / ds_verify) << "}" << (idx + 1 < rs.size() ? "," : "") << "\n";
    }
    os2 << "  ],\n";

    // r = 10 at the security budget (q_auth=2^32, lambda=128, p=65537).
    std::size_t r_budget = sketch_rows_for(f.p(), 128, 1ULL << 32);
    os2 << "  \"r_at_128bit_budget\": " << r_budget << ",\n";

    // Padding independence: verify time at r=10 for two logical paddings is the
    // same because verify never sees D (it is plaintext on the n x ell matrix).
    {
        SketchClientState cs;
        cs.k = sample(f, r_budget, n, 777);
        SketchServerView sv;
        sketch_register(f, cs, sv, "A", A);
        Program prog = Program::input("A").mul_right(B);
        Mat tp = sketch_prepare(f, cs, prog);
        double v = median_ms(WARM, TRIALS, [&]() {
            volatile bool ok = sketch_verify(f, cs, tp, C);
            (void)ok;
        });
        os2 << "  \"private_sketch_r10_verify_ms\": " << v << ",\n"
            << "  \"ratio_r10_to_dataseal\": " << (v / ds_verify) << "\n}\n";
    }

    std::ofstream of(out / "phase2_verify_audit.json");
    of << os2.str();
    std::cout << "wrote " << (out / "phase2_verify_audit.json").string() << "\n";
    return 0;
}
