#pragma once

#include <map>
#include <string>
#include <vector>

#include "dsf/matrix.hpp"
#include "dsf/sketch.hpp"

namespace dsf {

// A linear chain describing an approved program: it starts from one encrypted
// input and applies public right-multiplications, encrypted-input additions,
// and public offsets. This covers Y = C0 + sum_tau A_tau B_tau implemented as
// a sequential public right-linear/affine computation (guide 4.7).
struct ProgramStep {
    enum class Kind { Input, MulRight, AddInput, AddConst } kind;
    std::string label;
};

using ProgramChain = std::vector<ProgramStep>;

std::string emit_chain(const ProgramChain& chain);
ProgramChain parse_chain(const std::string& text);

// Builds a Program from the chain; operand labels for MulRight/AddConst are
// resolved against the public operand map.
Program build_program(const ProgramChain& chain, const std::map<std::string, Mat>& operands);

}  // namespace dsf
