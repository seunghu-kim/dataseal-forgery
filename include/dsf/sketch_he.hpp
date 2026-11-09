#pragma once

#include <map>
#include <string>

#include "dsf/he.hpp"
#include "dsf/sketch.hpp"
#include "dsf/sketch_program.hpp"

namespace dsf::he {

// Encrypts each registered input (data only) under the server's public key.
std::map<std::string, EncMatrix> encrypt_registered(const Context& ctx, const PublicKey& pk,
                                                    const SketchServerView& sv);

struct VerDecResult {
    bool shape_ok = false;
    bool accepted = false;
    Mat y;
};

// Verified decryption: confirm shape and context, decrypt Y', accept only if
// K Y' equals the client-prepared sketch T_P.
VerDecResult verdec(const Context& ctx, const PrivateKey& sk, const SketchClientState& cs, const Mat& expected_sketch,
                    const EncMatrix& y_enc, std::size_t expected_cols);

void write_program(const std::string& dir, const ProgramChain& chain);
ProgramChain read_program(const std::string& dir);

}  // namespace dsf::he
