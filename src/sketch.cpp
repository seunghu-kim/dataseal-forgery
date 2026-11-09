#include "dsf/sketch.hpp"

#include <stdexcept>
#include <vector>

namespace dsf {

namespace {

void require(bool cond, const char* msg) {
    if (!cond) throw std::invalid_argument(msg);
}

using Big = std::vector<std::uint32_t>;

Big big_from(std::uint64_t x) {
    Big b;
    while (x) {
        b.push_back(static_cast<std::uint32_t>(x));
        x >>= 32;
    }
    return b;
}

void big_mul(Big& a, std::uint64_t m) {
    u128 carry = 0;
    for (auto& limb : a) {
        u128 t = static_cast<u128>(limb) * m + carry;
        limb = static_cast<std::uint32_t>(t);
        carry = t >> 32;
    }
    while (carry) {
        a.push_back(static_cast<std::uint32_t>(carry));
        carry >>= 32;
    }
}

void big_shl(Big& a, unsigned bits) {
    for (unsigned i = 0; i < bits; ++i) big_mul(a, 2);
}

bool big_ge(const Big& a, const Big& b) {
    if (a.size() != b.size()) return a.size() > b.size();
    for (std::size_t i = a.size(); i-- > 0;)
        if (a[i] != b[i]) return a[i] > b[i];
    return true;
}

}  // namespace

std::size_t sketch_rows_for(std::uint64_t p, unsigned lambda_auth, std::uint64_t q_auth) {
    require(p >= 2 && q_auth >= 1, "invalid authentication parameters");
    Big target = big_from(q_auth);
    big_shl(target, lambda_auth);
    Big acc = big_from(1);
    std::size_t r = 0;
    while (!big_ge(acc, target)) {
        big_mul(acc, p);
        ++r;
    }
    return r;
}

Program Program::input(const std::string& label) {
    auto n = std::make_shared<ProgramNode>();
    n->kind = ProgramNode::Kind::Input;
    n->label = label;
    return Program(n);
}

Program Program::constant(const Mat& c) {
    auto n = std::make_shared<ProgramNode>();
    n->kind = ProgramNode::Kind::Constant;
    n->m = c;
    return Program(n);
}

Program Program::operator+(const Program& o) const {
    auto n = std::make_shared<ProgramNode>();
    n->kind = ProgramNode::Kind::Add;
    n->lhs = node_;
    n->rhs = o.node_;
    return Program(n);
}

Program Program::mul_right(const Mat& b) const {
    auto n = std::make_shared<ProgramNode>();
    n->kind = ProgramNode::Kind::MulRight;
    n->lhs = node_;
    n->m = b;
    return Program(n);
}

Mat Program::evaluate(const Field& f, const std::function<Mat(const std::string&)>& on_input,
                      const std::function<Mat(const Mat&)>& on_constant) const {
    auto add = [&](const Mat& a, const Mat& b) { return mat_add(f, a, b); };
    auto mul = [&](const Mat& a, const Mat& b) { return mat_mul(f, a, b); };
    return fold_program<Mat>(*node_, on_input, on_constant, add, mul);
}

SketchClientState sketch_keygen(const Field& f, std::size_t r, std::size_t n, OsRng& rng) {
    require(r >= 1 && n >= 1, "sketch dimensions must be positive");
    SketchClientState cs;
    cs.k = Mat(r, n);
    for (std::size_t i = 0; i < r; ++i)
        for (std::size_t j = 0; j < n; ++j) cs.k.at(i, j) = uniform_elem(f, rng);
    return cs;
}

void sketch_register(const Field& f, SketchClientState& cs, SketchServerView& sv, const std::string& label,
                     const Mat& a) {
    require(a.rows() == cs.k.cols(), "registered input must have n rows");
    require(cs.regs.count(label) == 0 && sv.inputs.count(label) == 0, "label already registered");
    cs.regs[label] = {a.rows(), a.cols(), mat_mul(f, cs.k, a)};
    sv.inputs[label] = a;
}

Mat sketch_eval(const Field& f, const SketchServerView& sv, const Program& prog) {
    return prog.evaluate(
        f,
        [&](const std::string& l) {
            auto it = sv.inputs.find(l);
            require(it != sv.inputs.end(), "unknown input label");
            return it->second;
        },
        [](const Mat& c) { return c; });
}

Mat sketch_prepare(const Field& f, const SketchClientState& cs, const Program& prog) {
    return prog.evaluate(
        f,
        [&](const std::string& l) {
            auto it = cs.regs.find(l);
            require(it != cs.regs.end(), "unknown input label");
            return it->second.w;
        },
        [&](const Mat& c) {
            require(c.rows() == cs.k.cols(), "constant must have n rows");
            return mat_mul(f, cs.k, c);
        });
}

bool sketch_verify(const Field& f, const SketchClientState& cs, const Mat& expected, const Mat& y) {
    if (y.rows() != cs.k.cols() || y.cols() != expected.cols()) return false;
    return mat_mul(f, cs.k, y) == expected;
}

}  // namespace dsf
