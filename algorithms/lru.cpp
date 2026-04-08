#include "algorithms/lru.h"

#include <algorithm>
#include <limits>
#include <sstream>
#include <unordered_map>

namespace amoe::algorithms {

SimulationResult run_lru(const std::vector<int>& reference_string, const std::size_t frame_count) {
    SimulationResult result;
    result.algorithm = AlgorithmType::LRU;

    std::vector<int> frames;
    std::unordered_map<int, std::size_t> last_used;
    frames.reserve(frame_count);

    for (std::size_t index = 0; index < reference_string.size(); ++index) {
        const int page = reference_string[index];
        SimulationStep step;
        step.index = index;
        step.page = page;

        auto it = std::find(frames.begin(), frames.end(), page);
        if (it == frames.end()) {
            step.page_fault = true;
            ++result.page_faults;

            if (frame_count == 0) {
                step.note = "No frames available.";
            } else if (frames.size() < frame_count) {
                frames.push_back(page);
                step.note = "Inserted page into empty frame.";
            } else {
                std::size_t oldest_index = std::numeric_limits<std::size_t>::max();
                auto victim_it = frames.begin();
                for (auto frame_it = frames.begin(); frame_it != frames.end(); ++frame_it) {
                    const std::size_t candidate_index = last_used[*frame_it];
                    if (candidate_index < oldest_index) {
                        oldest_index = candidate_index;
                        victim_it = frame_it;
                    }
                }

                const int victim = *victim_it;
                *victim_it = page;
                step.evicted_page = victim;
                ++result.eviction_counts[victim];

                std::ostringstream note;
                note << "Evicted least recently used page " << victim << '.';
                step.note = note.str();
            }
        } else {
            step.note = "Hit: page refreshed in LRU history.";
        }

        last_used[page] = index;
        step.frames = frames;
        result.steps.push_back(step);
    }

    return result;
}

} // namespace amoe::algorithms
