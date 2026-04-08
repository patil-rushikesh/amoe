#ifndef AMOE_ALGORITHMS_LRU_H
#define AMOE_ALGORITHMS_LRU_H

#include "common/types.h"

#include <vector>

namespace amoe::algorithms {

SimulationResult run_lru(const std::vector<int>& reference_string, std::size_t frame_count);

} // namespace amoe::algorithms

#endif
