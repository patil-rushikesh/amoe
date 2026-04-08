#include "algorithms/optimal.h"

#include <algorithm>
#include <limits>
#include <sstream>

namespace amoe::algorithms {

SimulationResult run_optimal(const std::vector<int>& reference_string, const std::size_t frame_count) {
    SimulationResult result;
    result.algorithm = AlgorithmType::Optimal;

    std::vector<int> frames;
    frames.reserve(frame_count);

    for (std::size_t index = 0; index < reference_string.size(); ++index) {
        const int page = reference_string[index];
        SimulationStep step;
        step.index = index;
        step.page = page;

        const bool hit = std::find(frames.begin(), frames.end(), page) != frames.end();
        if (!hit) {
            step.page_fault = true;
            ++result.page_faults;

            if (frame_count == 0) {
                step.note = "No frames available.";
            } else if (frames.size() < frame_count) {
                frames.push_back(page);
                step.note = "Inserted page into empty frame.";
            } else {
                std::size_t farthest_use = 0;
                auto victim_it = frames.begin();
                bool found_never_used = false;

                for (auto frame_it = frames.begin(); frame_it != frames.end(); ++frame_it) {
                    std::size_t next_use = std::numeric_limits<std::size_t>::max();
                    for (std::size_t future = index + 1; future < reference_string.size(); ++future) {
                        if (reference_string[future] == *frame_it) {
                            next_use = future;
                            break;
                        }
                    }

                    if (next_use == std::numeric_limits<std::size_t>::max()) {
                        victim_it = frame_it;
                        found_never_used = true;
                        break;
                    }

                    if (next_use > farthest_use) {
                        farthest_use = next_use;
                        victim_it = frame_it;
                    }
                }

                const int victim = *victim_it;
                *victim_it = page;
                step.evicted_page = victim;
                ++result.eviction_counts[victim];

                std::ostringstream note;
                if (found_never_used) {
                    note << "Evicted page " << victim << " because it does not reappear in the observed window.";
                } else {
                    note << "Evicted page " << victim << " with farthest future reuse.";
                }
                step.note = note.str();
            }
        } else {
            step.note = "Hit: page already resident.";
        }

        step.frames = frames;
        result.steps.push_back(step);
    }

    return result;
}

} // namespace amoe::algorithms
