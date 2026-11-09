#include <cstdlib>
#include <filesystem>
#include <set>
#include <string>

#include "dsf/he.hpp"
#include "dsf/he_io.hpp"
#include "dsf/rng.hpp"
#include "dsf/sketch.hpp"
#include "dsf/sketch_he.hpp"
#include "dsf/sketch_program.hpp"
#include "harness.hpp"

using namespace dsf;
namespace fs = std::filesystem;

namespace {

const he::Context& ctx() {
    static he::Context c = he::Context::create({});
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

std::string tmp_root(const std::string& name) {
    const char* env = std::getenv("DSF_TMP");
    fs::path root = env ? fs::path(env) : fs::temp_directory_path() / "dsf_test";
    fs::path dir = root / name;
    fs::remove_all(dir);
    fs::create_directories(dir);
    return dir.string();
}

std::size_t sketch_rows() { return sketch_rows_for(F().p(), 128, 1ULL << 32); }

}  // namespace

TEST(verdec_core_accepts_and_rejects) {
    OsRng os;
    const std::size_t n = 6;
    auto kp = he::keygen(ctx(), {"honest_minimal", false, {}});
    auto cs = sketch_keygen(F(), sketch_rows(), n, os);
    SketchServerView sv;
    sketch_register(F(), cs, sv, "A", sample(n, 4, 3));
    sketch_register(F(), cs, sv, "D", sample(n, 5, 4));
    auto enc = he::encrypt_registered(ctx(), kp.server.pk, sv);
    Mat b1 = sample(4, 5, 5), b2 = sample(5, 3, 6);

    ProgramChain chain{{ProgramStep::Kind::Input, "A"},
                       {ProgramStep::Kind::MulRight, "B1"},
                       {ProgramStep::Kind::AddInput, "D"},
                       {ProgramStep::Kind::MulRight, "B2"}};
    std::map<std::string, Mat> operands{{"B1", b1}, {"B2", b2}};
    Program prog = build_program(chain, operands);

    he::EncMatrix y = he::eval_program(ctx(), enc, prog);
    Mat tp = sketch_prepare(F(), cs, prog);

    auto ok = he::verdec(ctx(), kp.client.sk, cs, tp, y, 3);
    CHECK(ok.shape_ok && ok.accepted);
    CHECK(ok.y == mat_mul(F(), mat_add(F(), mat_mul(F(), sv.inputs.at("A"), b1), sv.inputs.at("D")), b2));

    Mat wrong_sketch = tp;
    wrong_sketch.at(0, 0) = F().add(wrong_sketch.at(0, 0), 1);
    CHECK(!he::verdec(ctx(), kp.client.sk, cs, wrong_sketch, y, 3).accepted);
    CHECK(!he::verdec(ctx(), kp.client.sk, cs, tp, y, 2).shape_ok);
}

TEST(two_programs_from_one_encoding) {
    OsRng os;
    const std::size_t n = 5;
    auto kp = he::keygen(ctx(), {"honest_minimal", false, {}});
    auto cs = sketch_keygen(F(), sketch_rows(), n, os);
    SketchServerView sv;
    sketch_register(F(), cs, sv, "A", sample(n, 4, 7));
    sketch_register(F(), cs, sv, "D", sample(n, 2, 8));
    auto enc = he::encrypt_registered(ctx(), kp.server.pk, sv);

    Program p1 = build_program({{ProgramStep::Kind::Input, "A"}, {ProgramStep::Kind::MulRight, "M"}}, {{"M", sample(4, 3, 9)}});
    Program p2 = build_program({{ProgramStep::Kind::Input, "A"},
                               {ProgramStep::Kind::MulRight, "M"},
                               {ProgramStep::Kind::AddInput, "D"}},
                              {{"M", sample(4, 2, 10)}});
    auto y1 = he::eval_program(ctx(), enc, p1);
    auto y2 = he::eval_program(ctx(), enc, p2);
    CHECK(he::verdec(ctx(), kp.client.sk, cs, sketch_prepare(F(), cs, p1), y1, 3).accepted);
    CHECK(he::verdec(ctx(), kp.client.sk, cs, sketch_prepare(F(), cs, p2), y2, 2).accepted);
    CHECK(!he::verdec(ctx(), kp.client.sk, cs, sketch_prepare(F(), cs, p1), y2, 2).accepted);
}

// A random output perturbation is rejected. This exercises the verifier; it is
// not an experimental proof of the q_auth * p^{-r} soundness bound.
TEST(random_perturbation_is_rejected) {
    OsRng os;
    const std::size_t n = 5;
    auto kp = he::keygen(ctx(), {"honest_minimal", false, {}});
    auto cs = sketch_keygen(F(), sketch_rows(), n, os);
    SketchServerView sv;
    sketch_register(F(), cs, sv, "A", sample(n, 4, 11));
    auto enc = he::encrypt_registered(ctx(), kp.server.pk, sv);
    Program prog = build_program({{ProgramStep::Kind::Input, "A"}, {ProgramStep::Kind::MulRight, "M"}}, {{"M", sample(4, 3, 12)}});
    Mat tp = sketch_prepare(F(), cs, prog);
    auto ok = he::verdec(ctx(), kp.client.sk, cs, tp, he::eval_program(ctx(), enc, prog), 3);
    CHECK(ok.accepted);
    int rejected = 0;
    SeededRng rng(999);
    for (int t = 0; t < 20; ++t) {
        Mat tampered = ok.y;
        tampered.at(uniform_elem(F(), rng) % n, uniform_elem(F(), rng) % 3) = uniform_nonzero_elem(F(), rng);
        if (tampered == ok.y) continue;
        if (!sketch_verify(F(), cs, tp, tampered)) ++rejected;
    }
    CHECK(rejected > 0);
}

TEST(server_bundle_has_no_secret_or_sketch) {
    OsRng os;
    const std::size_t n = 6;
    std::string dir = tmp_root("sketch_he_bundle");
    auto kp = he::keygen(ctx(), {"honest_minimal", false, {}});
    auto cs = sketch_keygen(F(), sketch_rows(), n, os);
    SketchServerView sv;
    sketch_register(F(), cs, sv, "A", sample(n, 4, 13));
    sketch_register(F(), cs, sv, "D", sample(n, 3, 14));
    he::write_server_bundle(dir, ctx(), kp.server, he::encrypt_registered(ctx(), kp.server.pk, sv),
                            {{"B1", sample(4, 3, 15)}, {"B2", sample(3, 2, 16)}});
    he::write_program(dir, {{ProgramStep::Kind::Input, "A"},
                            {ProgramStep::Kind::MulRight, "B1"},
                            {ProgramStep::Kind::AddInput, "D"},
                            {ProgramStep::Kind::MulRight, "B2"}});

    std::string sk_bytes = he::serialize_secret_key(kp.client.sk);
    std::string probe = sk_bytes.substr(sk_bytes.size() / 2, 64);
    for (const auto& name : he::list_files(dir)) {
        std::string body = he::read_file((fs::path(dir) / name).string());
        CHECK(body.find(probe) == std::string::npos);
    }
    std::set<std::string> files;
    for (const auto& n2 : he::list_files(dir)) files.insert(n2);
    CHECK(files.count("program.txt") == 1);
    for (const auto& name : files) CHECK(name.rfind("sketch", 0) == std::string::npos && name.find("secret") == std::string::npos);
}

TEST(separate_process_server_worker_produces_accepted_result) {
    const char* worker = std::getenv("DSF_WORKER");
    if (!worker) {
        CHECK(false && "DSF_WORKER not set");
        return;
    }
    OsRng os;
    const std::size_t n = 6;
    std::string root = tmp_root("sketch_he_worker");
    std::string bundle = root + "/server";
    std::string out = root + "/out";

    auto kp = he::keygen(ctx(), {"honest_minimal", false, {}});
    auto cs = sketch_keygen(F(), sketch_rows(), n, os);
    SketchServerView sv;
    sketch_register(F(), cs, sv, "A", sample(n, 4, 17));
    sketch_register(F(), cs, sv, "D", sample(n, 3, 18));
    Mat b1 = sample(4, 3, 19), b2 = sample(3, 2, 20);
    ProgramChain chain{{ProgramStep::Kind::Input, "A"},
                       {ProgramStep::Kind::MulRight, "B1"},
                       {ProgramStep::Kind::AddInput, "D"},
                       {ProgramStep::Kind::MulRight, "B2"}};
    he::write_server_bundle(bundle, ctx(), kp.server, he::encrypt_registered(ctx(), kp.server.pk, sv),
                            {{"B1", b1}, {"B2", b2}});
    he::write_program(bundle, chain);
    Program prog = build_program(chain, {{"B1", b1}, {"B2", b2}});
    Mat tp = sketch_prepare(F(), cs, prog);

    std::string cmd = std::string(worker) + " " + bundle + " " + out + " Y >/dev/null 2>&1";
    int rc = std::system(cmd.c_str());
    CHECK(rc == 0);

    he::EncMatrix y = he::read_matrix(out, "Y");
    auto r = he::verdec(ctx(), kp.client.sk, cs, tp, y, 2);
    CHECK(r.shape_ok && r.accepted);
    CHECK(r.y == mat_mul(F(), mat_add(F(), mat_mul(F(), sv.inputs.at("A"), b1), sv.inputs.at("D")), b2));
}

TEST_MAIN()
