#include "dsf/he_io.hpp"

#include <algorithm>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <stdexcept>

#include "ciphertext-ser.h"
#include "cryptocontext-ser.h"
#include "key/key-ser.h"
#include "scheme/bgvrns/bgvrns-ser.h"

namespace dsf::he {

using namespace lbcrypto;
namespace fs = std::filesystem;

namespace {

void require(bool cond, const std::string& msg) {
    if (!cond) throw std::runtime_error(msg);
}

void require_label(const std::string& l) {
    require(!l.empty() && std::all_of(l.begin(), l.end(), [](char c) { return std::isalnum(static_cast<unsigned char>(c)) || c == '_'; }),
            "invalid label: " + l);
}

std::string path(const std::string& dir, const std::string& name) { return (fs::path(dir) / name).string(); }

template <class T>
void save(const std::string& p, const T& obj) {
    require(Serial::SerializeToFile(p, obj, SerType::BINARY), "serialization failed: " + p);
}

template <class T>
void load(const std::string& p, T& obj) {
    require(Serial::DeserializeFromFile(p, obj, SerType::BINARY), "deserialization failed: " + p);
}

void write_plain(const std::string& p, const Mat& m) {
    std::ofstream os(p);
    os << m.rows() << " " << m.cols() << "\n";
    for (std::size_t i = 0; i < m.rows(); ++i) {
        for (std::size_t j = 0; j < m.cols(); ++j) os << (j ? " " : "") << m.at(i, j);
        os << "\n";
    }
    require(os.good(), "write failed: " + p);
}

Mat read_plain(const std::string& p) {
    std::ifstream is(p);
    std::size_t r = 0, c = 0;
    require(static_cast<bool>(is >> r >> c), "malformed operand: " + p);
    Mat m(r, c);
    for (std::size_t i = 0; i < r; ++i)
        for (std::size_t j = 0; j < c; ++j) require(static_cast<bool>(is >> m.at(i, j)), "malformed operand: " + p);
    return m;
}

void write_cts(const std::string& dir, const std::string& prefix, const EncMatrix& m) {
    for (std::size_t j = 0; j < m.cols; ++j) save(path(dir, prefix + "_" + std::to_string(j) + ".bin"), m.col[j]);
}

EncMatrix read_cts(const std::string& dir, const std::string& prefix, std::size_t rows, std::size_t cols) {
    EncMatrix m{rows, cols, {}};
    for (std::size_t j = 0; j < cols; ++j) {
        Ct ct;
        load(path(dir, prefix + "_" + std::to_string(j) + ".bin"), ct);
        m.col.push_back(ct);
    }
    return m;
}

}  // namespace

void clear_eval_keys() {
    CryptoContextImpl<Poly>::ClearEvalMultKeys();
    CryptoContextImpl<Poly>::ClearEvalAutomorphismKeys();
}

void reset_library_state() {
    CryptoContextImpl<Poly>::ClearEvalMultKeys();
    CryptoContextImpl<Poly>::ClearEvalAutomorphismKeys();
    CryptoContextFactory<Poly>::ReleaseAllContexts();
}

void write_server_bundle(const std::string& dir, const Context& ctx, const ServerKeys& keys,
                         const std::map<std::string, EncMatrix>& inputs,
                         const std::map<std::string, Mat>& public_operands) {
    fs::create_directories(dir);
    save(path(dir, "context.bin"), ctx.cc());
    save(path(dir, "public_key.bin"), keys.pk);
    if (keys.caps.relin_key) {
        std::ofstream os(path(dir, "eval_mult.bin"), std::ios::binary);
        require(CryptoContextImpl<Poly>::SerializeEvalMultKey(os, SerType::BINARY, ctx.cc()), "eval mult key serialization failed");
    }
    if (!keys.caps.rotations.empty()) {
        std::ofstream os(path(dir, "eval_rot.bin"), std::ios::binary);
        require(CryptoContextImpl<Poly>::SerializeEvalAutomorphismKey(os, SerType::BINARY, ctx.cc()),
                "rotation key serialization failed");
    }
    std::ofstream mf(path(dir, "manifest.txt"));
    mf << "format dsf-bundle-1\n";
    mf << "profile " << keys.caps.profile << "\n";
    mf << "relin_key " << (keys.caps.relin_key ? 1 : 0) << "\n";
    mf << "rotations";
    for (auto r : keys.caps.rotations) mf << " " << r;
    mf << "\n";
    for (const auto& [label, m] : inputs) {
        require_label(label);
        require_context(ctx, m);
        mf << "input " << label << " " << m.rows << " " << m.cols << "\n";
        write_cts(dir, "input_" + label, m);
    }
    for (const auto& [label, m] : public_operands) {
        require_label(label);
        mf << "operand " << label << "\n";
        write_plain(path(dir, "operand_" + label + ".txt"), m);
    }
    require(mf.good(), "manifest write failed");
}

ServerBundle read_server_bundle(const std::string& dir) {
    ServerBundle b;
    load(path(dir, "context.bin"), b.cc);
    load(path(dir, "public_key.bin"), b.keys.pk);
    std::ifstream mf(path(dir, "manifest.txt"));
    require(mf.good(), "missing manifest");
    std::string line;
    std::getline(mf, line);
    require(line == "format dsf-bundle-1", "unknown bundle format");
    while (std::getline(mf, line)) {
        std::istringstream ls(line);
        std::string key;
        ls >> key;
        if (key == "profile") {
            ls >> b.keys.caps.profile;
        } else if (key == "relin_key") {
            int v = 0;
            ls >> v;
            b.keys.caps.relin_key = v != 0;
        } else if (key == "rotations") {
            std::int32_t r;
            while (ls >> r) b.keys.caps.rotations.push_back(r);
        } else if (key == "input") {
            std::string label;
            std::size_t rows = 0, cols = 0;
            require(static_cast<bool>(ls >> label >> rows >> cols), "malformed input line");
            require_label(label);
            b.inputs[label] = read_cts(dir, "input_" + label, rows, cols);
        } else if (key == "operand") {
            std::string label;
            ls >> label;
            require_label(label);
            b.public_operands[label] = read_plain(path(dir, "operand_" + label + ".txt"));
        } else if (!key.empty()) {
            throw std::runtime_error("unknown manifest key: " + key);
        }
    }
    if (b.keys.caps.relin_key) {
        std::ifstream is(path(dir, "eval_mult.bin"), std::ios::binary);
        require(b.cc->DeserializeEvalMultKey(is, SerType::BINARY), "eval mult key deserialization failed");
    }
    if (!b.keys.caps.rotations.empty()) {
        std::ifstream is(path(dir, "eval_rot.bin"), std::ios::binary);
        require(b.cc->DeserializeEvalAutomorphismKey(is, SerType::BINARY), "rotation key deserialization failed");
    }
    return b;
}

void write_matrix(const std::string& dir, const std::string& label, const EncMatrix& m) {
    require_label(label);
    fs::create_directories(dir);
    std::ofstream mf(path(dir, "result_" + label + ".txt"));
    mf << m.rows << " " << m.cols << "\n";
    write_cts(dir, "result_" + label, m);
}

EncMatrix read_matrix(const std::string& dir, const std::string& label) {
    require_label(label);
    std::ifstream mf(path(dir, "result_" + label + ".txt"));
    std::size_t rows = 0, cols = 0;
    require(static_cast<bool>(mf >> rows >> cols), "missing result header");
    return read_cts(dir, "result_" + label, rows, cols);
}

void write_rowcipher(const std::string& dir, const std::string& label, const RowCipher& rc) {
    require_label(label);
    fs::create_directories(dir);
    const RowLayout& l = rc.layout;
    std::ofstream mf(path(dir, "row_" + label + ".txt"));
    mf << l.logical_rows << " " << l.logical_cols << " " << l.orig_rows << " " << l.dim << "\n";
    require(mf.good(), "row layout write failed");
    save(path(dir, "row_" + label + ".bin"), rc.ct);
}

RowCipher read_rowcipher(const std::string& dir, const std::string& label) {
    require_label(label);
    std::ifstream mf(path(dir, "row_" + label + ".txt"));
    std::size_t lr = 0, lc = 0, dr = 0, d = 0;
    require(static_cast<bool>(mf >> lr >> lc >> dr >> d), "missing row layout header");
    RowCipher rc;
    rc.layout = make_layout(lr, lc, dr, d);
    load(path(dir, "row_" + label + ".bin"), rc.ct);
    return rc;
}

void write_client_secret(const std::string& dir, const ClientKeys& keys) {
    fs::create_directories(dir);
    save(path(dir, "secret_key.bin"), keys.sk);
}

ClientKeys read_client_secret(const std::string& dir) {
    ClientKeys k;
    load(path(dir, "secret_key.bin"), k.sk);
    return k;
}

std::string serialize_secret_key(const PrivateKey& sk) {
    std::stringstream ss;
    Serial::Serialize(sk, ss, SerType::BINARY);
    return ss.str();
}

std::size_t serialized_bytes(const Ct& ct) {
    std::stringstream ss;
    Serial::Serialize(ct, ss, SerType::BINARY);
    return ss.str().size();
}

std::vector<std::string> list_files(const std::string& dir) {
    std::vector<std::string> out;
    for (const auto& e : fs::directory_iterator(dir))
        if (e.is_regular_file()) out.push_back(e.path().filename().string());
    std::sort(out.begin(), out.end());
    return out;
}

std::string read_file(const std::string& p) {
    std::ifstream is(p, std::ios::binary);
    std::ostringstream ss;
    ss << is.rdbuf();
    return ss.str();
}

}  // namespace dsf::he
