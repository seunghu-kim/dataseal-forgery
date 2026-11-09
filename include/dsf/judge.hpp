#pragma once

#include "dsf/matrix.hpp"

namespace dsf {

struct Attempt {
    bool accepted = false;
    bool wrong_output = false;
    bool unchanged = false;

    bool forged() const { return accepted && wrong_output; }
};

Attempt judge(bool accepted, const Mat& returned_full, const Mat& honest_full, const Mat& returned_data,
              const Mat& correct_data);

}  // namespace dsf
