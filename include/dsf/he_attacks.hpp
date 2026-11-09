#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <vector>

#include "dsf/attacks.hpp"
#include "dsf/he.hpp"
#include "dsf/he_rowmajor.hpp"

namespace dsf::he {

// A trace of rotation indices actually used by the transformations.
// Each index must belong to matmul_rotation_indices(layout.dim).
struct RotationAudit {
    std::vector<std::int32_t> used;
};

// Changes data rows and the first checksum row by a public scalar while
// leaving the second checksum row unchanged. Expects the two-row DataSeal
// matrix-multiplication layout with logical rows [0,n+2).
RowCipher selective_scaling(const Context& ctx, const RowCipher& evaluated,
                            std::size_t n, Elem factor);

// Produces a ciphertext that has the encrypted vector
//   h_i = w_b * A_{i,a} - w_a * A_{i,b}
// in column choice.target of the data rows, and zero in the other rows/slots.
// The checksum row of encoded_input is at logical row n.
// Only matrix-multiplication evaluation keys may be used.
Ct encrypted_kernel_column(const Context& ctx, const RowCipher& encoded_input,
                           const Capabilities& available, std::size_t n,
                           KernelChoice choice, RotationAudit* audit = nullptr);

// Adds the encrypted kernel column to a separately evaluated output without
// altering any of its checksum rows. The input and output must have the same
// padded square dimension, but they may have different logical column counts.
RowCipher kernel_adjusted_output(const Context& ctx, const RowCipher& encoded_input,
                                 const RowCipher& evaluated, const Capabilities& available,
                                 std::size_t n, KernelChoice choice,
                                 RotationAudit* audit = nullptr);

// Swaps two data rows in one column, or in all columns when col is omitted.
// This operation leaves checksum rows and all other slots unchanged.
RowCipher square_permute(const Context& ctx, const RowCipher& evaluated,
                         const Capabilities& available, std::size_t n,
                         std::size_t r1, std::size_t r2,
                         std::optional<std::size_t> col = std::nullopt,
                         RotationAudit* audit = nullptr);

// Applies reciprocal public factors to two different data-row entries of a
// single column. Both checksum rows and unrelated entries are unchanged.
RowCipher square_rescale(const Context& ctx, const RowCipher& evaluated,
                         std::size_t n, std::size_t col,
                         std::size_t r1, std::size_t r2, Elem gamma);

// Sets one output data column to zero, leaving its checksum unchanged.
// This is a separate conditional case, meaningful only when its honest
// column product is zero.
RowCipher square_zero_column(const Context& ctx, const RowCipher& evaluated,
                             std::size_t n, std::size_t col);

}  // namespace dsf::he
