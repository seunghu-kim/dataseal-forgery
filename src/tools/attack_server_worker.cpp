#include <fstream>
#include <iostream>
#include <sstream>
#include <string>

#include "dsf/he.hpp"
#include "dsf/he_attacks.hpp"
#include "dsf/he_io.hpp"
#include "dsf/he_rowmajor.hpp"

using namespace dsf;

// Standalone adversary: given only a serialized public bundle directory, it
// reads the public key, declared evaluation keys, the encrypted encoded input
// and the honest encrypted output, applies the encrypted kernel transformation,
// and writes the modified ciphertext. It never reads a client/secret directory.
int main(int argc, char** argv) {
    if (argc != 3) {
        std::cerr << "usage: dsf_attack_server_worker <bundle_dir> <out_dir>\n";
        return 2;
    }
    const std::string bundle_dir = argv[1];
    const std::string out_dir = argv[2];
    try {
        he::reset_library_state();
        he::ServerBundle bundle = he::read_server_bundle(bundle_dir);
        he::Context ctx = he::Context::adopt(bundle.cc);

        he::RowCipher input = he::read_rowcipher(bundle_dir, "input");
        he::RowCipher honest = he::read_rowcipher(bundle_dir, "honest");

        std::ifstream pf((bundle_dir + "/attack_params.txt").c_str());
        std::size_t n = 0, col_a = 0, col_b = 0, target = 0;
        if (!(pf >> n >> col_a >> col_b >> target)) throw std::runtime_error("bad attack_params.txt");

        KernelChoice choice{col_a, col_b, target};
        he::RotationAudit audit;
        he::RowCipher forged =
            he::kernel_adjusted_output(ctx, input, honest, bundle.keys.caps, n, choice, &audit);
        he::write_rowcipher(out_dir, "forged", forged);

        std::ofstream af((out_dir + "/rotation_audit.txt").c_str());
        af << audit.used.size();
        for (auto r : audit.used) af << " " << r;
        af << "\n";
    } catch (const std::exception& e) {
        std::cerr << "worker error: " << e.what() << "\n";
        return 1;
    }
    std::cout << "ok\n";
    return 0;
}
