#pragma once

#include <map>
#include <string>
#include <vector>

#include "dsf/he.hpp"
#include "dsf/he_rowmajor.hpp"

namespace dsf::he {

struct ServerBundle {
    CC cc;
    ServerKeys keys;
    std::map<std::string, EncMatrix> inputs;
    std::map<std::string, Mat> public_operands;
};

void reset_library_state();
void clear_eval_keys();

void write_server_bundle(const std::string& dir, const Context& ctx, const ServerKeys& keys,
                         const std::map<std::string, EncMatrix>& inputs,
                         const std::map<std::string, Mat>& public_operands);
ServerBundle read_server_bundle(const std::string& dir);

void write_matrix(const std::string& dir, const std::string& label, const EncMatrix& m);
EncMatrix read_matrix(const std::string& dir, const std::string& label);

void write_rowcipher(const std::string& dir, const std::string& label, const RowCipher& rc);
RowCipher read_rowcipher(const std::string& dir, const std::string& label);

void write_client_secret(const std::string& dir, const ClientKeys& keys);
ClientKeys read_client_secret(const std::string& dir);

std::string serialize_secret_key(const PrivateKey& sk);
std::size_t serialized_bytes(const Ct& ct);
std::vector<std::string> list_files(const std::string& dir);
std::string read_file(const std::string& path);

}  // namespace dsf::he
