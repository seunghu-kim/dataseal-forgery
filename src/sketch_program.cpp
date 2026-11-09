#include "dsf/sketch_program.hpp"

#include <sstream>
#include <stdexcept>

namespace dsf {

namespace {

void require(bool cond, const std::string& msg) {
    if (!cond) throw std::invalid_argument(msg);
}

const char* kind_tag(ProgramStep::Kind k) {
    switch (k) {
        case ProgramStep::Kind::Input: return "INPUT";
        case ProgramStep::Kind::MulRight: return "MUL_RIGHT";
        case ProgramStep::Kind::AddInput: return "ADD_INPUT";
        case ProgramStep::Kind::AddConst: return "ADD_CONST";
    }
    return "?";
}

}  // namespace

std::string emit_chain(const ProgramChain& chain) {
    std::ostringstream os;
    for (const auto& s : chain) os << kind_tag(s.kind) << " " << s.label << "\n";
    return os.str();
}

ProgramChain parse_chain(const std::string& text) {
    ProgramChain chain;
    std::istringstream is(text);
    std::string tag, label;
    while (is >> tag >> label) {
        ProgramStep s;
        if (tag == "INPUT")
            s.kind = ProgramStep::Kind::Input;
        else if (tag == "MUL_RIGHT")
            s.kind = ProgramStep::Kind::MulRight;
        else if (tag == "ADD_INPUT")
            s.kind = ProgramStep::Kind::AddInput;
        else if (tag == "ADD_CONST")
            s.kind = ProgramStep::Kind::AddConst;
        else
            throw std::invalid_argument("unknown program step: " + tag);
        s.label = label;
        chain.push_back(s);
    }
    return chain;
}

Program build_program(const ProgramChain& chain, const std::map<std::string, Mat>& operands) {
    require(!chain.empty() && chain.front().kind == ProgramStep::Kind::Input, "chain must start with INPUT");
    auto operand = [&](const std::string& l) -> const Mat& {
        auto it = operands.find(l);
        require(it != operands.end(), "missing operand: " + l);
        return it->second;
    };
    Program acc = Program::input(chain.front().label);
    for (std::size_t i = 1; i < chain.size(); ++i) {
        const ProgramStep& s = chain[i];
        switch (s.kind) {
            case ProgramStep::Kind::Input:
                throw std::invalid_argument("INPUT may only appear first");
            case ProgramStep::Kind::MulRight:
                acc = acc.mul_right(operand(s.label));
                break;
            case ProgramStep::Kind::AddInput:
                acc = acc + Program::input(s.label);
                break;
            case ProgramStep::Kind::AddConst:
                acc = acc + Program::constant(operand(s.label));
                break;
        }
    }
    return acc;
}

}  // namespace dsf
