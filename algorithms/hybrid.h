#ifndef AMOE_ALGORITHMS_HYBRID_H
#define AMOE_ALGORITHMS_HYBRID_H

#include "common/types.h"

#include <vector>

namespace amoe::algorithms {

SimulationResult run_hybrid(const std::vector<int>& reference_string, std::size_t frame_count, const AlgorithmContext& context);

} // namespace amoe::algorithms

#endif
