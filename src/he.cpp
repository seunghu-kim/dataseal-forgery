#include "dsf/he.hpp"

#include <sstream>
#include <stdexcept>

namespace dsf::he {

using namespace lbcrypto;

namespace {

void require(bool cond, const std::string& msg) {
    if (!cond) throw std::invalid_argument(msg);
}

Plaintext packed(const Context& ctx, const std::vector<std::int64_t>& v) { return ctx.cc()->MakePackedPlaintext(v); }

Plaintext constant_pt(const Context& ctx, Elem c) {
    return packed(ctx, std::vector<std::int64_t>(ctx.slots(), ctx.field().centered(c)));
}

Plaintext column_pt(const Context& ctx, const Vec& col) {
    std::vector<std::int64_t> v(ctx.slots(), 0);
    for (std::size_t i = 0; i < col.size(); ++i) v[i] = ctx.field().centered(col[i]);
    return packed(ctx, v);
}

template <class T>
std::string to_str(const T& x) {
    std::ostringstream os;
    os << x;
    return os.str();
}

}  // namespace

Context Context::create(const ContextSpec& spec) {
    CCParams<CryptoContextBGVRNS> params;
    params.SetPlaintextModulus(spec.p);
    params.SetMultiplicativeDepth(spec.depth);
    params.SetSecurityLevel(HEStd_128_classic);
    if (spec.ring_dim) params.SetRingDim(spec.ring_dim);
    CC cc = GenCryptoContext(params);
    cc->Enable(PKE);
    cc->Enable(KEYSWITCH);
    cc->Enable(LEVELEDSHE);
    Context ctx = adopt(cc);
    std::uint64_t two_n = 2ULL * ctx.ring_dim();
    if ((spec.p - 1) % two_n != 0)
        throw std::invalid_argument("plaintext modulus does not split completely: 2N must divide p-1");
    return ctx;
}

Context Context::adopt(const CC& cc) {
    return Context(cc, Field(cc->GetCryptoParameters()->GetPlaintextModulus()));
}

std::uint32_t Context::ring_dim() const { return cc_->GetRingDimension(); }

std::size_t Context::slots() const { return cc_->GetEncodingParams()->GetBatchSize(); }

std::string Context::describe_json() const {
    auto cp = std::dynamic_pointer_cast<CryptoParametersRNS>(cc_->GetCryptoParameters());
    const auto& towers = cc_->GetElementParams()->GetParams();
    std::ostringstream os;
    os << "{\n";
    os << "  \"scheme\": \"BGVRNS\",\n";
    os << "  \"plaintext_modulus\": " << field_.p() << ",\n";
    os << "  \"ring_dimension\": " << ring_dim() << ",\n";
    os << "  \"batch_size\": " << slots() << ",\n";
    os << "  \"rotation_row_slots\": " << row_slots() << ",\n";
    os << "  \"ciphertext_modulus_bits\": " << cc_->GetModulus().GetMSB() << ",\n";
    os << "  \"tower_count\": " << towers.size() << ",\n";
    os << "  \"tower_bits\": [";
    for (std::size_t i = 0; i < towers.size(); ++i)
        os << (i ? ", " : "") << towers[i]->GetModulus().GetMSB();
    os << "],\n";
    os << "  \"scaling_technique\": \"" << (cp ? to_str(cp->GetScalingTechnique()) : "unknown") << "\",\n";
    os << "  \"key_switch_technique\": \"" << (cp ? to_str(cp->GetKeySwitchTechnique()) : "unknown") << "\",\n";
    os << "  \"security_request\": \"" << to_str(cp->GetStdLevel()) << "\"\n";
    os << "}\n";
    return os.str();
}

KeyPair keygen(const Context& ctx, const Capabilities& caps) {
    auto kp = ctx.cc()->KeyGen();
    if (!kp.good()) throw std::runtime_error("key generation failed");
    if (caps.relin_key) ctx.cc()->EvalMultKeyGen(kp.secretKey);
    if (!caps.rotations.empty()) ctx.cc()->EvalAtIndexKeyGen(kp.secretKey, caps.rotations);
    return {{kp.secretKey}, {kp.publicKey, caps}};
}

void require_context(const Context& ctx, const EncMatrix& m) {
    require(m.col.size() == m.cols, "encrypted matrix column count mismatch");
    for (const auto& ct : m.col) {
        require(ct != nullptr, "null ciphertext");
        require(ct->GetCryptoContext() == ctx.cc(), "ciphertext belongs to a different crypto context");
    }
}

EncMatrix encrypt_matrix(const Context& ctx, const PublicKey& pk, const Mat& a) {
    require(a.rows() >= 1 && a.cols() >= 1, "empty matrix");
    require(a.rows() <= ctx.row_slots(), "column exceeds rotation-row capacity");
    EncMatrix m{a.rows(), a.cols(), {}};
    for (std::size_t j = 0; j < a.cols(); ++j) {
        m.col.push_back(ctx.cc()->Encrypt(pk, column_pt(ctx, a.col(j))));
        ++ctx.counts().encrypt;
    }
    return m;
}

std::vector<std::int64_t> decrypt_slots(const Context& ctx, const PrivateKey& sk, const Ct& ct) {
    Plaintext pt;
    DecryptResult r = ctx.cc()->Decrypt(sk, ct, &pt);
    ++ctx.counts().decrypt;
    if (!r.isValid) throw std::runtime_error("decryption reported invalid result");
    pt->SetLength(ctx.slots());
    return pt->GetPackedValue();
}

Mat decrypt_matrix(const Context& ctx, const PrivateKey& sk, const EncMatrix& m) {
    require_context(ctx, m);
    Mat out(m.rows, m.cols);
    for (std::size_t j = 0; j < m.cols; ++j) {
        auto v = decrypt_slots(ctx, sk, m.col[j]);
        for (std::size_t i = 0; i < m.rows; ++i) out.at(i, j) = ctx.field().from_int(v[i]);
        for (std::size_t i = m.rows; i < v.size(); ++i)
            if (ctx.field().from_int(v[i]) != 0) throw std::runtime_error("nonzero padding slot");
    }
    return out;
}

EncMatrix matmul_public(const Context& ctx, const EncMatrix& a, const Mat& b) {
    require_context(ctx, a);
    require(a.cols == b.rows(), "public matmul shape mismatch");
    EncMatrix out{a.rows, b.cols(), {}};
    for (std::size_t j = 0; j < b.cols(); ++j) {
        Ct acc;
        for (std::size_t l = 0; l < a.cols; ++l) {
            Ct term = ctx.cc()->EvalMult(a.col[l], constant_pt(ctx, b.at(l, j)));
            ++ctx.counts().mult_pt;
            if (!acc) {
                acc = term;
            } else {
                acc = ctx.cc()->EvalAdd(acc, term);
                ++ctx.counts().add_ct;
            }
        }
        out.col.push_back(acc);
    }
    return out;
}

EncMatrix add(const Context& ctx, const EncMatrix& a, const EncMatrix& b) {
    require_context(ctx, a);
    require_context(ctx, b);
    require(a.rows == b.rows && a.cols == b.cols, "encrypted addition shape mismatch");
    EncMatrix out{a.rows, a.cols, {}};
    for (std::size_t j = 0; j < a.cols; ++j) {
        out.col.push_back(ctx.cc()->EvalAdd(a.col[j], b.col[j]));
        ++ctx.counts().add_ct;
    }
    return out;
}

EncMatrix add_plain(const Context& ctx, const EncMatrix& a, const Mat& c) {
    require_context(ctx, a);
    require(a.rows == c.rows() && a.cols == c.cols(), "plaintext offset shape mismatch");
    EncMatrix out{a.rows, a.cols, {}};
    for (std::size_t j = 0; j < a.cols; ++j) {
        Plaintext pt = column_pt(ctx, c.col(j));
        out.col.push_back(ctx.cc()->EvalAdd(a.col[j], pt));
        ++ctx.counts().add_pt;
    }
    return out;
}

EncMatrix square(const Context& ctx, const EncMatrix& a) {
    require_context(ctx, a);
    EncMatrix out{a.rows, a.cols, {}};
    for (std::size_t j = 0; j < a.cols; ++j) {
        out.col.push_back(ctx.cc()->EvalMult(a.col[j], a.col[j]));
        ++ctx.counts().mult_ct;
    }
    return out;
}

namespace {

struct Value {
    bool plain = false;
    Mat m;
    EncMatrix e;
};

}  // namespace

EncMatrix eval_program(const Context& ctx, const std::map<std::string, EncMatrix>& inputs, const Program& prog) {
    const Field& f = ctx.field();
    auto on_input = [&](const std::string& l) {
        auto it = inputs.find(l);
        require(it != inputs.end(), "unknown input label: " + l);
        return Value{false, {}, it->second};
    };
    auto on_const = [&](const Mat& c) { return Value{true, c, {}}; };
    auto on_add = [&](const Value& x, const Value& y) {
        if (x.plain && y.plain) return Value{true, mat_add(f, x.m, y.m), {}};
        if (x.plain) return Value{false, {}, add_plain(ctx, y.e, x.m)};
        if (y.plain) return Value{false, {}, add_plain(ctx, x.e, y.m)};
        return Value{false, {}, add(ctx, x.e, y.e)};
    };
    auto on_mul = [&](const Value& x, const Mat& b) {
        if (x.plain) return Value{true, mat_mul(f, x.m, b), {}};
        return Value{false, {}, matmul_public(ctx, x.e, b)};
    };
    Value v = fold_program<Value>(prog.root(), on_input, on_const, on_add, on_mul);
    require(!v.plain, "program has no encrypted input");
    return v.e;
}

}  // namespace dsf::he
