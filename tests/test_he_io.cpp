#include <cstdlib>
#include <filesystem>
#include <set>

#include "dsf/dataseal.hpp"
#include "dsf/he.hpp"
#include "dsf/he_io.hpp"
#include "dsf/he_rowmajor.hpp"
#include "dsf/rng.hpp"
#include "harness.hpp"

using namespace dsf;
namespace fs = std::filesystem;

namespace {

std::string tmp_root(const std::string& name) {
    const char* env = std::getenv("DSF_TMP");
    fs::path root = env ? fs::path(env) : fs::temp_directory_path() / "dsf_test";
    fs::path dir = root / name;
    fs::remove_all(dir);
    fs::create_directories(dir);
    return dir.string();
}

Mat sample(const Field& f, std::size_t r, std::size_t c, std::uint64_t seed) {
    SeededRng rng(seed);
    Mat m(r, c);
    for (std::size_t i = 0; i < r; ++i)
        for (std::size_t j = 0; j < c; ++j) m.at(i, j) = uniform_elem(f, rng);
    return m;
}

bool contains_secret(const std::string& dir, const std::string& sk_bytes) {
    const std::size_t len = 64;
    const std::string probe = sk_bytes.substr(sk_bytes.size() / 2, len);
    for (const auto& name : he::list_files(dir))
        if (he::read_file((fs::path(dir) / name).string()).find(probe) != std::string::npos) return true;
    return false;
}

he::Context client_context(const he::ClientKeys& k) { return he::Context::adopt(k.sk->GetCryptoContext()); }

}  // namespace

TEST(matmul_bundle_roundtrip_without_secret) {
    std::string root = tmp_root("matmul");
    std::string server_dir = root + "/server", client_dir = root + "/client", out_dir = root + "/out";
    MatmulClientState client_state;
    std::string sk_bytes;
    {
        he::Context ctx = he::Context::create({});
        auto kp = he::keygen(ctx, {"honest_minimal", false, {}});
        OsRng os;
        const Field& f = ctx.field();
        auto enc = matmul_encode(f, sample(f, 5, 3, 1), sample(f, 3, 2, 2), matmul_keygen(f, 5, os));
        client_state = enc.client;
        he::write_server_bundle(server_dir, ctx, kp.server, {{"Astar", he::encrypt_matrix(ctx, kp.server.pk, enc.server.a_star)}},
                                {{"B", enc.server.b}});
        he::write_client_secret(client_dir, kp.client);
        sk_bytes = he::serialize_secret_key(kp.client.sk);
    }
    std::set<std::string> files;
    for (const auto& n : he::list_files(server_dir)) files.insert(n);
    std::set<std::string> expected{"context.bin", "input_Astar_0.bin", "input_Astar_1.bin", "input_Astar_2.bin",
                                   "manifest.txt", "operand_B.txt", "public_key.bin"};
    CHECK(files == expected);
    CHECK(!contains_secret(server_dir, sk_bytes));
    CHECK(contains_secret(client_dir, sk_bytes));

    he::reset_library_state();
    {
        he::ServerBundle b = he::read_server_bundle(server_dir);
        he::Context sctx = he::Context::adopt(b.cc);
        CHECK(b.keys.caps.profile == "honest_minimal" && !b.keys.caps.relin_key && b.keys.caps.rotations.empty());
        he::write_matrix(out_dir, "C", he::matmul_public(sctx, b.inputs.at("Astar"), b.public_operands.at("B")));
    }
    CHECK(!contains_secret(out_dir, sk_bytes));

    he::reset_library_state();
    auto ck = he::read_client_secret(client_dir);
    he::Context cctx = client_context(ck);
    Mat out = he::decrypt_matrix(cctx, ck.sk, he::read_matrix(out_dir, "C"));
    CHECK(matmul_verify(cctx.field(), client_state, out, MatmulVerifier::Strengthened).accepted());
    CHECK(matmul_verify(cctx.field(), client_state, out, MatmulVerifier::Original).accepted());
}

TEST(square_bundle_carries_relin_key) {
    he::reset_library_state();
    std::string root = tmp_root("square");
    std::string server_dir = root + "/server", client_dir = root + "/client", out_dir = root + "/out";
    SquareClientState client_state;
    std::string sk_bytes;
    {
        he::Context ctx = he::Context::create({});
        auto kp = he::keygen(ctx, {"honest_minimal", true, {}});
        OsRng os;
        const Field& f = ctx.field();
        auto enc = square_encode(f, sample(f, 4, 2, 3), square_keygen(f, 2, os));
        client_state = enc.client;
        he::write_server_bundle(server_dir, ctx, kp.server, {{"Astar", he::encrypt_matrix(ctx, kp.server.pk, enc.server.a_star)}}, {});
        he::write_client_secret(client_dir, kp.client);
        sk_bytes = he::serialize_secret_key(kp.client.sk);
    }
    CHECK(fs::exists(server_dir + "/eval_mult.bin"));
    CHECK(!fs::exists(server_dir + "/eval_rot.bin"));
    CHECK(!contains_secret(server_dir, sk_bytes));

    he::reset_library_state();
    {
        he::ServerBundle b = he::read_server_bundle(server_dir);
        he::Context sctx = he::Context::adopt(b.cc);
        he::write_matrix(out_dir, "C", he::square(sctx, b.inputs.at("Astar")));
    }
    he::reset_library_state();
    auto ck = he::read_client_secret(client_dir);
    he::Context cctx = client_context(ck);
    Mat out = he::decrypt_matrix(cctx, ck.sk, he::read_matrix(out_dir, "C"));
    CHECK(square_verify(cctx.field(), client_state, out).accepted());
}

TEST(server_without_relin_key_cannot_square) {
    he::reset_library_state();
    std::string root = tmp_root("norelin");
    {
        he::Context ctx = he::Context::create({});
        auto kp = he::keygen(ctx, {"honest_minimal", false, {}});
        he::write_server_bundle(root, ctx, kp.server, {{"A", he::encrypt_matrix(ctx, kp.server.pk, Mat(3, 1))}}, {});
    }
    he::reset_library_state();
    he::ServerBundle b = he::read_server_bundle(root);
    he::Context sctx = he::Context::adopt(b.cc);
    CHECK_THROWS(he::square(sctx, b.inputs.at("A")));
}

TEST(sketch_bundle_is_data_only) {
    he::reset_library_state();
    std::string root = tmp_root("sketch");
    std::string server_dir = root + "/server", client_dir = root + "/client";
    const std::size_t n = 5;
    {
        he::Context ctx = he::Context::create({});
        auto kp = he::keygen(ctx, {"honest_minimal", false, {}});
        OsRng os;
        const Field& f = ctx.field();
        auto cs = sketch_keygen(f, 10, n, os);
        SketchServerView sv;
        sketch_register(f, cs, sv, "A", sample(f, n, 3, 4));
        he::write_server_bundle(server_dir, ctx, kp.server, {{"A", he::encrypt_matrix(ctx, kp.server.pk, sv.inputs.at("A"))}}, {});
        he::write_client_secret(client_dir, kp.client);
    }
    std::string manifest = he::read_file(server_dir + "/manifest.txt");
    CHECK(manifest.find("input A 5 3") != std::string::npos);
    CHECK(manifest.find("operand") == std::string::npos);
    he::reset_library_state();
    auto ck = he::read_client_secret(client_dir);
    he::Context cctx = client_context(ck);
    he::ServerBundle b = he::read_server_bundle(server_dir);
    for (const auto& c : b.inputs.at("A").col) {
        auto slots = he::decrypt_slots(cctx, ck.sk, c);
        for (std::size_t i = n; i < slots.size(); ++i) CHECK(slots[i] == 0);
    }
}

TEST(rowcipher_roundtrip_preserves_layout_and_content) {
    he::reset_library_state();
    std::string dir = tmp_root("rowcipher");
    Mat m = sample(Field(65537), 4, 3, 77);
    {
        he::Context ctx = he::Context::create({});
        auto kp = he::keygen(ctx, {"honest_minimal", false, {}});
        he::RowLayout lay = he::make_layout(4, 3, 2, 5);
        he::write_rowcipher(dir, "X", he::encrypt_rowmajor(ctx, kp.server.pk, m, lay));
        he::write_client_secret(dir, kp.client);
    }
    he::reset_library_state();
    auto ck = he::read_client_secret(dir);
    he::Context cctx = he::Context::adopt(ck.sk->GetCryptoContext());
    he::RowCipher rc = he::read_rowcipher(dir, "X");
    CHECK(rc.layout.logical_rows == 4 && rc.layout.logical_cols == 3 && rc.layout.dim == 5 &&
          rc.layout.data_rows.size() == 2);
    CHECK(he::decrypt_rowmajor(cctx, ck.sk, rc) == m);
}

TEST_MAIN()
