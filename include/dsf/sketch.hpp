#pragma once

#include <cstddef>
#include <cstdint>
#include <functional>
#include <map>
#include <memory>
#include <stdexcept>
#include <string>
#include <utility>

#include "dsf/field.hpp"
#include "dsf/matrix.hpp"
#include "dsf/rng.hpp"

namespace dsf {

std::size_t sketch_rows_for(std::uint64_t p, unsigned lambda_auth, std::uint64_t q_auth);

struct ProgramNode {
    enum class Kind { Input, Constant, Add, MulRight } kind;
    std::string label;
    Mat m;
    std::shared_ptr<const ProgramNode> lhs, rhs;
};

class Program {
public:
    static Program input(const std::string& label);
    static Program constant(const Mat& c);

    Program operator+(const Program& o) const;
    Program mul_right(const Mat& b) const;

    Mat evaluate(const Field& f, const std::function<Mat(const std::string&)>& on_input,
                 const std::function<Mat(const Mat&)>& on_constant) const;

    const ProgramNode& root() const { return *node_; }

private:
    explicit Program(std::shared_ptr<const ProgramNode> n) : node_(std::move(n)) {}
    std::shared_ptr<const ProgramNode> node_;
};

template <class T, class OnInput, class OnConst, class OnAdd, class OnMul>
T fold_program(const ProgramNode& n, OnInput& on_input, OnConst& on_const, OnAdd& on_add, OnMul& on_mul) {
    switch (n.kind) {
        case ProgramNode::Kind::Input: return on_input(n.label);
        case ProgramNode::Kind::Constant: return on_const(n.m);
        case ProgramNode::Kind::Add:
            return on_add(fold_program<T>(*n.lhs, on_input, on_const, on_add, on_mul),
                          fold_program<T>(*n.rhs, on_input, on_const, on_add, on_mul));
        case ProgramNode::Kind::MulRight:
            return on_mul(fold_program<T>(*n.lhs, on_input, on_const, on_add, on_mul), n.m);
    }
    throw std::logic_error("unreachable");
}

struct SketchRegistration {
    std::size_t rows = 0, cols = 0;
    Mat w;
};

struct SketchClientState {
    Mat k;
    std::map<std::string, SketchRegistration> regs;
};

struct SketchServerView {
    std::map<std::string, Mat> inputs;
};

SketchClientState sketch_keygen(const Field& f, std::size_t r, std::size_t n, OsRng& rng);
void sketch_register(const Field& f, SketchClientState& cs, SketchServerView& sv, const std::string& label,
                     const Mat& a);
Mat sketch_eval(const Field& f, const SketchServerView& sv, const Program& prog);
Mat sketch_prepare(const Field& f, const SketchClientState& cs, const Program& prog);
bool sketch_verify(const Field& f, const SketchClientState& cs, const Mat& expected, const Mat& y);

}  // namespace dsf
