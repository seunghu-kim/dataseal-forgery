#include <iostream>
#include <string>

#include "dsf/he.hpp"
#include "dsf/he_io.hpp"
#include "dsf/sketch_he.hpp"
#include "dsf/sketch_program.hpp"

using namespace dsf;

// Standalone server: given only a serialized public bundle directory, it reads
// Enc(A_tau) inputs, the public operands, and the approved program, evaluates
// it homomorphically, and writes the encrypted result. It never reads a client
// or secret directory.
int main(int argc, char** argv) {
    if (argc != 4) {
        std::cerr << "usage: dsf_sketch_server_worker <bundle_dir> <out_dir> <result_label>\n";
        return 2;
    }
    const std::string bundle_dir = argv[1];
    const std::string out_dir = argv[2];
    const std::string label = argv[3];
    try {
        he::reset_library_state();
        he::ServerBundle bundle = he::read_server_bundle(bundle_dir);
        he::Context ctx = he::Context::adopt(bundle.cc);
        ProgramChain chain = he::read_program(bundle_dir);
        Program prog = build_program(chain, bundle.public_operands);
        he::EncMatrix y = he::eval_program(ctx, bundle.inputs, prog);
        he::write_matrix(out_dir, label, y);
    } catch (const std::exception& e) {
        std::cerr << "worker error: " << e.what() << "\n";
        return 1;
    }
    std::cout << "ok\n";
    return 0;
}
