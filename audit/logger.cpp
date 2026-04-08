#include "audit/logger.h"

#include "common/utils.h"

#include <fstream>
#include <iomanip>
#include <sstream>

namespace amoe {

AuditLogger::AuditLogger(std::string log_path) : log_path_(std::move(log_path)) {}

bool AuditLogger::log(const AuditEntry& entry, std::string& error) const {
    std::ofstream output(log_path_, std::ios::app);
    if (!output.is_open()) {
        error = "unable to open audit log";
        return false;
    }

    output << "{\"timestamp\":\"" << utils::escape_json(entry.timestamp) << "\","
           << "\"process\":\"" << utils::escape_json(entry.process_name) << "\","
           << "\"pid\":" << entry.pid << ','
           << "\"action\":\"" << to_string(entry.action) << "\","
           << "\"user_decision\":\"" << utils::escape_json(entry.user_decision) << "\","
           << "\"algorithm\":\"" << to_string(entry.algorithm) << "\","
           << "\"reason\":\"" << utils::escape_json(entry.reason) << "\","
           << "\"risk\":\"" << to_string(entry.risk) << "\","
           << "\"confidence\":" << std::fixed << std::setprecision(2) << entry.confidence << ','
           << "\"executed\":" << (entry.executed ? "true" : "false") << ','
           << "\"success\":" << (entry.success ? "true" : "false") << ','
           << "\"memory_mb\":" << std::fixed << std::setprecision(2) << entry.memory_mb << ','
           << "\"previous_priority\":" << entry.previous_priority << ','
           << "\"new_priority\":" << entry.new_priority << "}\n";

    return true;
}

const std::string& AuditLogger::path() const {
    return log_path_;
}

} // namespace amoe
