#include "algorithms/hybrid.h"

#include <algorithm>
#include <limits>
#include <sstream>
#include <unordered_map>

namespace amoe::algorithms {

namespace {

double lookup_or_default(const std::unordered_map<int, double>& values, const int key, const double fallback) {
    const auto it = values.find(key);
    return it == values.end() ? fallback : it->second;
}

} // namespace

SimulationResult run_hybrid(const std::vector<int>& reference_string,
                            const std::size_t frame_count,
                            const AlgorithmContext& context) {
    SimulationResult result;
    result.algorithm = AlgorithmType::Hybrid;

    std::vector<int> frames;
    std::unordered_map<int, std::size_t> last_seen;
    std::unordered_map<int, std::size_t> seen_count;
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
                auto victim_it = frames.begin();
                double lowest_score = std::numeric_limits<double>::max();
                std::size_t max_seen_count = 1;
                for (const auto& [seen_page, count] : seen_count) {
                    (void)seen_page;
                    max_seen_count = std::max(max_seen_count, count);
                }

                for (auto frame_it = frames.begin(); frame_it != frames.end(); ++frame_it) {
                    const int candidate = *frame_it;
                    const auto history_it = last_seen.find(candidate);
                    const double recency_component =
                        history_it == last_seen.end() ? 0.0 : 1.0 / (1.0 + static_cast<double>(index - history_it->second));
                    const double frequency_component =
                        seen_count.empty() ? 0.0 : static_cast<double>(seen_count[candidate]) / static_cast<double>(max_seen_count);
                    const double memory_component = lookup_or_default(context.memory_usage, candidate, 0.5);
                    const double score = (context.weights.recency * recency_component) +
                                         (context.weights.frequency * frequency_component) +
                                         (context.weights.memory_usage * memory_component);

                    if (score < lowest_score) {
                        lowest_score = score;
                        victim_it = frame_it;
                    }
                }

                const int victim = *victim_it;
                *victim_it = page;
                step.evicted_page = victim;
                ++result.eviction_counts[victim];

                std::ostringstream note;
                note << "Evicted page " << victim << " with lowest hybrid retention score " << lowest_score << '.';
                step.note = note.str();
            }
        } else {
            step.note = "Hit: page retained by hybrid scoring.";
        }

        ++seen_count[page];
        last_seen[page] = index;
        step.frames = frames;
        result.steps.push_back(step);
    }

    return result;
}

} // namespace amoe::algorithms
