#include "dsf/judge.hpp"

namespace dsf {

Attempt judge(bool accepted, const Mat& returned_full, const Mat& honest_full, const Mat& returned_data,
              const Mat& correct_data) {
    Attempt a;
    a.accepted = accepted;
    a.wrong_output = returned_data != correct_data;
    a.unchanged = returned_full == honest_full;
    return a;
}

}  // namespace dsf
