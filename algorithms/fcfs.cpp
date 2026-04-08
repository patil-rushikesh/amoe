#include "algorithms/fcfs.h"

#include <algorithm>
#include <deque>
#include <sstream>

namespace amoe::algorithms {

SimulationResult run_fcfs(const std::vector<int>& reference_string, const std::size_t frame_count) {
    SimulationResult result;
    result.algorithm = AlgorithmType::FCFS;

    std::vector<int> frames;
    std::deque<int> insertion_order;
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
                insertion_order.push_back(page);
                step.note = "Inserted page into empty frame.";
            } else {
                const int victim = insertion_order.front();
                insertion_order.pop_front();
                auto victim_it = std::find(frames.begin(), frames.end(), victim);
                if (victim_it != frames.end()) {
                    *victim_it = page;
                }
                insertion_order.push_back(page);
                step.evicted_page = victim;
                ++result.eviction_counts[victim];

                std::ostringstream note;
                note << "Evicted oldest page " << victim << " and inserted " << page << '.';
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
