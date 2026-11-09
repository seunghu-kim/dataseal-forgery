#include "dsf/sketch_he.hpp"

#include <filesystem>
#include <fstream>
#include <sstream>
#include <stdexcept>

namespace dsf::he {

namespace fs = std::filesystem;

std::map<std::string, EncMatrix> encrypt_registered(const Context& ctx, const PublicKey& pk,
                                                    const SketchServerView& sv) {
    std::map<std::string, EncMatrix> out;
    for (const auto& [label, m] : sv.inputs) out[label] = encrypt_matrix(ctx, pk, m);
    return out;
}

VerDecResult verdec(const Context& ctx, const PrivateKey& sk, const SketchClientState& cs, const Mat& expected_sketch,
                    const EncMatrix& y_enc, std::size_t expected_cols) {
    VerDecResult r;
    r.shape_ok = y_enc.rows == cs.k.cols() && y_enc.cols == expected_cols && y_enc.col.size() == y_enc.cols;
    if (!r.shape_ok) return r;
    for (const auto& ct : y_enc.col)
        if (ct == nullptr || ct->GetCryptoContext() != ctx.cc()) return r;
    r.shape_ok = true;
    r.y = decrypt_matrix(ctx, sk, y_enc);
    r.accepted = sketch_verify(ctx.field(), cs, expected_sketch, r.y);
    return r;
}

void write_program(const std::string& dir, const ProgramChain& chain) {
    fs::create_directories(dir);
    std::ofstream os((fs::path(dir) / "program.txt").string());
    os << emit_chain(chain);
    if (!os.good()) throw std::runtime_error("failed to write program");
}

ProgramChain read_program(const std::string& dir) {
    std::ifstream is((fs::path(dir) / "program.txt").string());
    if (!is.good()) throw std::runtime_error("missing program.txt");
    std::ostringstream ss;
    ss << is.rdbuf();
    return parse_chain(ss.str());
}

}  // namespace dsf::he
