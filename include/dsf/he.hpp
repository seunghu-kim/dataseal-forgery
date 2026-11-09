#pragma once

#include <cstddef>
#include <cstdint>
#include <map>
#include <string>
#include <vector>

#include "openfhe.h"

#include "dsf/field.hpp"
#include "dsf/matrix.hpp"
#include "dsf/sketch.hpp"

namespace dsf::he {

using Poly = lbcrypto::DCRTPoly;
using CC = lbcrypto::CryptoContext<Poly>;
using Ct = lbcrypto::Ciphertext<Poly>;
using PublicKey = lbcrypto::PublicKey<Poly>;
using PrivateKey = lbcrypto::PrivateKey<Poly>;

struct ContextSpec {
    std::uint64_t p = 65537;
    std::uint32_t depth = 2;
    std::uint32_t ring_dim = 0;
};

struct Capabilities {
    std::string profile = "honest_minimal";
    bool relin_key = false;
    std::vector<std::int32_t> rotations;
};

struct OpCounts {
    std::uint64_t encrypt = 0, decrypt = 0;
    std::uint64_t add_ct = 0, add_pt = 0;
    std::uint64_t mult_pt = 0, mult_ct = 0;
    std::uint64_t rotate = 0;

    void reset() { *this = OpCounts{}; }
};

class Context {
public:
    static Context create(const ContextSpec& spec);
    static Context adopt(const CC& cc);

    const CC& cc() const { return cc_; }
    const Field& field() const { return field_; }
    std::uint32_t ring_dim() const;
    std::size_t slots() const;
    std::size_t row_slots() const { return slots() / 2; }

    OpCounts& counts() const { return counts_; }
    std::string describe_json() const;

private:
    Context(CC cc, Field f) : cc_(std::move(cc)), field_(f) {}
    CC cc_;
    Field field_;
    mutable OpCounts counts_;
};

struct ClientKeys {
    PrivateKey sk;
};

struct ServerKeys {
    PublicKey pk;
    Capabilities caps;
};

struct KeyPair {
    ClientKeys client;
    ServerKeys server;
};

KeyPair keygen(const Context& ctx, const Capabilities& caps);

struct EncMatrix {
    std::size_t rows = 0, cols = 0;
    std::vector<Ct> col;
};

void require_context(const Context& ctx, const EncMatrix& m);

EncMatrix encrypt_matrix(const Context& ctx, const PublicKey& pk, const Mat& a);
Mat decrypt_matrix(const Context& ctx, const PrivateKey& sk, const EncMatrix& m);
std::vector<std::int64_t> decrypt_slots(const Context& ctx, const PrivateKey& sk, const Ct& ct);

EncMatrix matmul_public(const Context& ctx, const EncMatrix& a, const Mat& b);
EncMatrix add(const Context& ctx, const EncMatrix& a, const EncMatrix& b);
EncMatrix add_plain(const Context& ctx, const EncMatrix& a, const Mat& c);
EncMatrix square(const Context& ctx, const EncMatrix& a);
EncMatrix eval_program(const Context& ctx, const std::map<std::string, EncMatrix>& inputs, const Program& prog);

}  // namespace dsf::he
