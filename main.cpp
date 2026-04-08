#include "audit/audit_reader.h"
#include "audit/logger.h"
#include "common/utils.h"
#include "config/config.h"
#include "decision/engine.h"
#include "monitor/tracker.h"
#include "security/permissions.h"
#include "security/safety.h"
#include "system/process_manager.h"
#include "ui/cli.h"

#include <iostream>
#include <optional>
#include <string>
#include <vector>

namespace amoe {

namespace {

struct CliOverrides {
    std::string config_path {"amoe.conf"};
    std::optional<std::size_t> frames;
    std::optional<std::size_t> samples;
    std::optional<std::size_t> interval_ms;
    std::optional<std::size_t> max_recommendations;
    std::optional<Mode> mode;
    bool show_logs {false};
    bool undo_last {false};
    bool list_only {false};
    bool help {false};
    int filter_pid {-1};
    std::string filter_action;
    std::string filter_decision;
};

struct ActionOutcome {
    bool executed {false};
    bool success {false};
    std::string message;
    int new_priority {0};
};

void print_usage() {
    std::cout << "Usage: amoe [options]\n";
    std::cout << "  --config <path>\n";
    std::cout << "  --frames <n>\n";
    std::cout << "  --samples <n>\n";
    std::cout << "  --interval-ms <n>\n";
    std::cout << "  --max-recommendations <n>\n";
    std::cout << "  --mode beginner|advanced|auto|dry-run\n";
    std::cout << "  --view-logs\n";
    std::cout << "  --filter-pid <pid>\n";
    std::cout << "  --filter-action <action>\n";
    std::cout << "  --filter-decision <decision>\n";
    std::cout << "  --undo-last\n";
    std::cout << "  --list-only\n";
    std::cout << "  --help\n";
}

std::optional<std::string> next_value(const int argc, char* argv[], int& index) {
    if (index + 1 >= argc) {
        return std::nullopt;
    }
    ++index;
    return std::string(argv[index]);
}

bool parse_arguments(const int argc, char* argv[], CliOverrides& overrides) {
    for (int index = 1; index < argc; ++index) {
        const std::string arg = argv[index];
        if (arg == "--config") {
            const auto value = next_value(argc, argv, index);
            if (!value) {
                return false;
            }
            overrides.config_path = *value;
        } else if (arg == "--frames") {
            const auto value = next_value(argc, argv, index);
            if (!value) {
                return false;
            }
            const auto parsed = utils::to_int(*value);
            if (!parsed || *parsed <= 0) {
                return false;
            }
            overrides.frames = static_cast<std::size_t>(*parsed);
        } else if (arg == "--samples") {
            const auto value = next_value(argc, argv, index);
            if (!value) {
                return false;
            }
            const auto parsed = utils::to_int(*value);
            if (!parsed || *parsed <= 0) {
                return false;
            }
            overrides.samples = static_cast<std::size_t>(*parsed);
        } else if (arg == "--interval-ms") {
            const auto value = next_value(argc, argv, index);
            if (!value) {
                return false;
            }
            const auto parsed = utils::to_int(*value);
            if (!parsed || *parsed <= 0) {
                return false;
            }
            overrides.interval_ms = static_cast<std::size_t>(*parsed);
        } else if (arg == "--max-recommendations") {
            const auto value = next_value(argc, argv, index);
            if (!value) {
                return false;
            }
            const auto parsed = utils::to_int(*value);
            if (!parsed || *parsed <= 0) {
                return false;
            }
            overrides.max_recommendations = static_cast<std::size_t>(*parsed);
        } else if (arg == "--mode") {
            const auto value = next_value(argc, argv, index);
            if (!value) {
                return false;
            }
            overrides.mode = utils::parse_mode(*value, Mode::Beginner);
        } else if (arg == "--view-logs") {
            overrides.show_logs = true;
        } else if (arg == "--filter-pid") {
            const auto value = next_value(argc, argv, index);
            if (!value) {
                return false;
            }
            const auto parsed = utils::to_int(*value);
            if (!parsed) {
                return false;
            }
            overrides.filter_pid = *parsed;
        } else if (arg == "--filter-action") {
            const auto value = next_value(argc, argv, index);
            if (!value) {
                return false;
            }
            overrides.filter_action = *value;
        } else if (arg == "--filter-decision") {
            const auto value = next_value(argc, argv, index);
            if (!value) {
                return false;
            }
            overrides.filter_decision = *value;
        } else if (arg == "--undo-last") {
            overrides.undo_last = true;
        } else if (arg == "--list-only") {
            overrides.list_only = true;
        } else if (arg == "--help") {
            overrides.help = true;
        } else {
            return false;
        }
    }
    return true;
}

void apply_overrides(const CliOverrides& overrides, RuntimeConfig& config) {
    if (overrides.frames.has_value()) {
        config.frames = *overrides.frames;
    }
    if (overrides.samples.has_value()) {
        config.samples = *overrides.samples;
    }
    if (overrides.interval_ms.has_value()) {
        config.interval_ms = *overrides.interval_ms;
    }
    if (overrides.max_recommendations.has_value()) {
        config.max_recommendations = *overrides.max_recommendations;
    }
    if (overrides.mode.has_value()) {
        config.mode = *overrides.mode;
    }
}

ActionOutcome execute_action(ProcessManager& process_manager, const SafetyManager& safety, const Recommendation& recommendation) {
    ActionOutcome outcome;
    std::string reason;
    if (!safety.can_execute(recommendation.action, recommendation.process, reason)) {
        outcome.message = reason;
        return outcome;
    }

    outcome.executed = true;
    std::string error;
    switch (recommendation.action) {
    case ActionType::Suspend:
        outcome.success = process_manager.suspend_process(recommendation.process.pid, error);
        outcome.message = outcome.success ? "Process suspended." : error;
        break;
    case ActionType::Kill:
        outcome.success = process_manager.kill_process(recommendation.process.pid, error);
        outcome.message = outcome.success ? "Process termination requested." : error;
        break;
    case ActionType::LowerPriority:
        outcome.success = process_manager.change_priority(recommendation.process.pid, recommendation.proposed_priority, error);
        outcome.new_priority = recommendation.proposed_priority;
        outcome.message = outcome.success ? "Process priority lowered." : error;
        break;
    default:
        outcome.executed = false;
        outcome.success = false;
        outcome.message = "Unsupported action.";
        break;
    }
    return outcome;
}

AuditEntry make_audit_entry(const Recommendation& recommendation,
                            const std::string& decision,
                            const ActionOutcome& outcome,
                            const std::string& reason_override = {}) {
    AuditEntry entry;
    entry.timestamp = utils::format_now();
    entry.process_name = recommendation.process.name;
    entry.pid = recommendation.process.pid;
    entry.action = recommendation.action;
    entry.user_decision = decision;
    entry.algorithm = recommendation.selected_algorithm;
    entry.reason = reason_override.empty() ? recommendation.reason : reason_override;
    entry.risk = recommendation.risk;
    entry.confidence = recommendation.confidence;
    entry.executed = outcome.executed;
    entry.success = outcome.success;
    entry.memory_mb = recommendation.estimated_memory_reclaim_mb;
    entry.previous_priority = recommendation.previous_priority;
    entry.new_priority = outcome.new_priority;
    return entry;
}

void persist_audit(const AuditLogger& logger, const AuditEntry& entry, const Cli& cli) {
    std::string error;
    if (!logger.log(entry, error)) {
        cli.print_action_result("Audit logging failed: " + error, false);
    }
}

} // namespace

} // namespace amoe

int main(int argc, char* argv[]) {
    using namespace amoe;

    CliOverrides overrides;
    if (!parse_arguments(argc, argv, overrides)) {
        print_usage();
        return 1;
    }
    if (overrides.help) {
        print_usage();
        return 0;
    }

    ConfigManager config_manager;
    RuntimeConfig config = config_manager.load(overrides.config_path);
    apply_overrides(overrides, config);

    PermissionManager permission_manager;
    const PermissionStatus permissions = permission_manager.query();

    auto process_manager = ProcessManager::create();
    SafetyManager safety(config, permissions);
    AuditLogger audit_logger(config.audit_log_path);
    AuditReader audit_reader(config.audit_log_path);
    Cli cli;

    if (overrides.show_logs) {
        AuditFilter filter;
        filter.pid = overrides.filter_pid;
        if (!overrides.filter_action.empty()) {
            filter.action = utils::parse_action(overrides.filter_action);
        }
        filter.decision = overrides.filter_decision;
        cli.print_log_entries(audit_reader.read(filter));
        return 0;
    }

    if (overrides.undo_last) {
        cli.print_banner();
        const auto last_action = audit_reader.last_reversible_action();
        if (!last_action.has_value()) {
            cli.print_action_result("No reversible action found in audit log.", true);
            return 0;
        }

        ActionOutcome outcome;
        outcome.executed = true;
        std::string error;
        if (last_action->action == ActionType::Suspend) {
            outcome.success = process_manager->resume_process(last_action->pid, error);
            outcome.message = outcome.success ? "Suspended process resumed." : error;
        } else if (last_action->action == ActionType::LowerPriority) {
            outcome.success = process_manager->change_priority(last_action->pid, last_action->previous_priority, error);
            outcome.message = outcome.success ? "Process priority restored." : error;
            outcome.new_priority = last_action->previous_priority;
        } else {
            outcome.executed = false;
            outcome.success = false;
            outcome.message = "Last action cannot be undone.";
        }

        AuditEntry undo_entry;
        undo_entry.timestamp = utils::format_now();
        undo_entry.process_name = last_action->process_name;
        undo_entry.pid = last_action->pid;
        undo_entry.action = last_action->action == ActionType::Suspend ? ActionType::Resume : ActionType::LowerPriority;
        undo_entry.user_decision = "UNDO";
        undo_entry.algorithm = last_action->algorithm;
        undo_entry.reason = "Undo requested by user.";
        undo_entry.risk = RiskLevel::Low;
        undo_entry.confidence = 1.0;
        undo_entry.executed = outcome.executed;
        undo_entry.success = outcome.success;
        undo_entry.memory_mb = last_action->memory_mb;
        undo_entry.previous_priority = last_action->new_priority;
        undo_entry.new_priority = outcome.new_priority;

        persist_audit(audit_logger, undo_entry, cli);
        cli.print_action_result(outcome.message, outcome.success);
        return outcome.success ? 0 : 1;
    }

    ProcessTracker tracker(*process_manager, safety, config);
    const MonitoringReport monitoring = tracker.collect();

    cli.print_banner();
    if (monitoring.snapshots.empty()) {
        cli.print_action_result("Unable to collect process information.", false);
        return 1;
    }

    cli.print_environment(monitoring.snapshots.back(), config, process_manager->platform_name(), permissions);

    DecisionEngine engine(config, permissions);
    const AnalysisReport analysis = engine.evaluate(monitoring);
    cli.print_algorithm_comparison(analysis, monitoring.system_state);

    if (analysis.recommendations.empty()) {
        cli.print_no_recommendations(monitoring.system_state);
        return 0;
    }

    if (overrides.list_only) {
        for (const auto& recommendation : analysis.recommendations) {
            cli.print_recommendation(recommendation);
        }
        return 0;
    }

    for (const auto& recommendation : analysis.recommendations) {
        bool handled = false;
        while (!handled) {
            cli.print_recommendation(recommendation);
            const int choice = cli.prompt_choice(recommendation, config.mode);
            if (choice == 4) {
                cli.print_details(recommendation, analysis, monitoring.system_state);
                continue;
            }

            if (choice == 3) {
                std::string config_error;
                const bool saved = config_manager.add_protected_process(overrides.config_path, config,
                                                                       recommendation.process, config_error);
                ActionOutcome outcome;
                outcome.executed = false;
                outcome.success = saved;
                outcome.message = saved ? "Process added to protected list." : config_error;
                persist_audit(audit_logger,
                              make_audit_entry(recommendation, "ALWAYS_IGNORE", outcome, "Process added to user whitelist."),
                              cli);
                cli.print_action_result(outcome.message, outcome.success);
                handled = true;
                continue;
            }

            if (choice != 1) {
                ActionOutcome outcome;
                outcome.executed = false;
                outcome.success = true;
                outcome.message = "Recommendation skipped.";
                persist_audit(audit_logger, make_audit_entry(recommendation, "NO", outcome, "User skipped recommendation."), cli);
                cli.print_action_result(outcome.message, outcome.success);
                handled = true;
                continue;
            }

            if (config.mode == Mode::DryRun) {
                ActionOutcome outcome;
                outcome.executed = false;
                outcome.success = true;
                outcome.message = "Dry-run mode enabled. No live action executed.";
                persist_audit(audit_logger,
                              make_audit_entry(recommendation, "YES (DRY_RUN)", outcome, "Dry-run mode prevented execution."),
                              cli);
                cli.print_action_result(outcome.message, outcome.success);
                handled = true;
                continue;
            }

            if (!cli.confirm_action(recommendation)) {
                ActionOutcome outcome;
                outcome.executed = false;
                outcome.success = true;
                outcome.message = "Action cancelled by user.";
                persist_audit(audit_logger, make_audit_entry(recommendation, "NO", outcome, "User cancelled confirmation."), cli);
                cli.print_action_result(outcome.message, outcome.success);
                handled = true;
                continue;
            }

            const ActionOutcome outcome = execute_action(*process_manager, safety, recommendation);
            persist_audit(audit_logger, make_audit_entry(recommendation, "YES", outcome), cli);
            cli.print_action_result(outcome.message, outcome.success);
            handled = true;
        }
    }

    return 0;
}
