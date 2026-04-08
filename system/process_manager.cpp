#include "system/process_manager.h"

#include "common/utils.h"

#include <algorithm>
#include <cctype>
#include <cerrno>
#include <cmath>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <stdexcept>

#if defined(__linux__)
#include <csignal>
#include <dirent.h>
#include <pwd.h>
#include <sys/resource.h>
#include <sys/types.h>
#include <unistd.h>
#elif defined(_WIN32)
#define NOMINMAX
#include <windows.h>
#include <psapi.h>
#include <tlhelp32.h>
#else
#include <csignal>
#include <cstdio>
#include <pwd.h>
#include <sys/resource.h>
#include <sys/types.h>
#include <unistd.h>
#if defined(__APPLE__)
#include <libproc.h>
#include <mach/host_info.h>
#include <mach/mach.h>
#include <sys/sysctl.h>
#endif
#endif

namespace amoe {

namespace {

bool is_numeric_directory(const std::string& name) {
    return !name.empty() && std::all_of(name.begin(), name.end(), [](unsigned char ch) { return std::isdigit(ch) != 0; });
}

std::string read_text_file(const std::filesystem::path& path) {
    std::ifstream input(path);
    if (!input.is_open()) {
        return {};
    }
    std::ostringstream out;
    out << input.rdbuf();
    return out.str();
}

std::string uid_to_username(const std::uint64_t uid) {
#if defined(_WIN32)
    (void)uid;
    return {};
#else
    if (const passwd* pw = getpwuid(static_cast<uid_t>(uid))) {
        return pw->pw_name;
    }
    return std::to_string(uid);
#endif
}

#if defined(__linux__)

class LinuxProcessManager final : public ProcessManager {
  public:
    std::vector<ProcessInfo> list_processes() override {
        std::vector<ProcessInfo> processes;
        const auto now = Clock::now();
        const long ticks_per_second = sysconf(_SC_CLK_TCK);
        const long cpu_count = std::max(1L, sysconf(_SC_NPROCESSORS_ONLN));
        const double uptime_seconds = read_system_uptime();

        for (const auto& entry : std::filesystem::directory_iterator("/proc")) {
            if (!entry.is_directory()) {
                continue;
            }
            const auto name = entry.path().filename().string();
            if (!is_numeric_directory(name)) {
                continue;
            }
            const int pid = std::stoi(name);
            ProcessInfo process;
            process.pid = pid;
            process.observed_at = now;
            process.last_active = now;

            if (!populate_status(entry.path(), process)) {
                continue;
            }
            populate_stat(entry.path(), process, uptime_seconds, ticks_per_second, cpu_count);
            process.priority = getpriority(PRIO_PROCESS, pid);
            processes.push_back(process);
        }

        std::sort(processes.begin(), processes.end(),
                  [](const ProcessInfo& left, const ProcessInfo& right) { return left.rss_kb > right.rss_kb; });
        return processes;
    }

    MemoryStatus memory_status() override {
        MemoryStatus memory;
        std::ifstream input("/proc/meminfo");
        std::string key;
        std::uint64_t value = 0;
        std::string unit;
        while (input >> key >> value >> unit) {
            if (key == "MemTotal:") {
                memory.total_kb = value;
            } else if (key == "MemAvailable:") {
                memory.available_kb = value;
            } else if (key == "MemFree:" && memory.available_kb == 0) {
                memory.available_kb = value;
            }
        }
        if (memory.total_kb > memory.available_kb) {
            memory.used_kb = memory.total_kb - memory.available_kb;
        }
        if (memory.total_kb > 0) {
            memory.pressure_percent = (static_cast<double>(memory.used_kb) / static_cast<double>(memory.total_kb)) * 100.0;
        }
        return memory;
    }

    bool suspend_process(const int pid, std::string& error) override {
        return signal_action(pid, SIGSTOP, error, "suspend");
    }

    bool resume_process(const int pid, std::string& error) override {
        return signal_action(pid, SIGCONT, error, "resume");
    }

    bool kill_process(const int pid, std::string& error) override {
        return signal_action(pid, SIGTERM, error, "kill");
    }

    bool change_priority(const int pid, const int priority, std::string& error) override {
        if (setpriority(PRIO_PROCESS, pid, priority) != 0) {
            error = "setpriority failed: " + std::string(std::strerror(errno));
            return false;
        }
        return true;
    }

    std::string platform_name() const override {
        return "Linux /proc";
    }

  private:
    static double read_system_uptime() {
        std::ifstream input("/proc/uptime");
        double uptime = 0.0;
        input >> uptime;
        return uptime;
    }

    static bool populate_status(const std::filesystem::path& proc_path, ProcessInfo& process) {
        std::ifstream input(proc_path / "status");
        if (!input.is_open()) {
            return false;
        }

        std::string line;
        uid_t uid = 0;
        while (std::getline(input, line)) {
            if (line.rfind("Name:", 0) == 0) {
                process.name = utils::trim(line.substr(5));
            } else if (line.rfind("VmRSS:", 0) == 0) {
                const auto parts = utils::split(utils::trim(line.substr(6)), ' ');
                if (!parts.empty()) {
                    if (const auto parsed = utils::to_int(parts.front())) {
                        process.rss_kb = static_cast<std::uint64_t>(*parsed);
                    }
                }
            } else if (line.rfind("Uid:", 0) == 0) {
                std::istringstream uid_stream(line.substr(4));
                uid_stream >> uid;
            } else if (line.rfind("State:", 0) == 0) {
                process.state = utils::trim(line.substr(6));
            }
        }

        process.owner = uid_to_username(uid);
        process.system_process = (process.pid == 0 || process.pid == 1);
        return !process.name.empty();
    }

    static void populate_stat(const std::filesystem::path& proc_path,
                              ProcessInfo& process,
                              const double uptime_seconds,
                              const long ticks_per_second,
                              const long cpu_count) {
        const auto stat_content = read_text_file(proc_path / "stat");
        if (stat_content.empty()) {
            return;
        }

        const auto closing = stat_content.rfind(')');
        if (closing == std::string::npos || closing + 2 >= stat_content.size()) {
            return;
        }
        std::istringstream stream(stat_content.substr(closing + 2));
        std::vector<std::string> fields;
        std::string value;
        while (stream >> value) {
            fields.push_back(value);
        }
        if (fields.size() < 20) {
            return;
        }

        const auto utime = std::stoull(fields[11]);
        const auto stime = std::stoull(fields[12]);
        const auto starttime = std::stoull(fields[19]);
        process.cpu_time_ticks = utime + stime;

        const double seconds = uptime_seconds - (static_cast<double>(starttime) / static_cast<double>(ticks_per_second));
        if (seconds > 0.0) {
            process.cpu_percent = ((static_cast<double>(process.cpu_time_ticks) / static_cast<double>(ticks_per_second)) / seconds) * 100.0 /
                                  static_cast<double>(cpu_count);
        }
    }

    static bool signal_action(const int pid, const int signal, std::string& error, const std::string& action_name) {
        if (::kill(pid, signal) != 0) {
            error = action_name + " failed: " + std::string(std::strerror(errno));
            return false;
        }
        return true;
    }
};

#endif

#if defined(_WIN32)

class WindowsProcessManager final : public ProcessManager {
  public:
    std::vector<ProcessInfo> list_processes() override {
        std::vector<ProcessInfo> processes;
        HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (snapshot == INVALID_HANDLE_VALUE) {
            return processes;
        }

        PROCESSENTRY32 entry {};
        entry.dwSize = sizeof(entry);
        if (!Process32First(snapshot, &entry)) {
            CloseHandle(snapshot);
            return processes;
        }

        const auto now = Clock::now();
        const DWORD cpu_count = std::max<DWORD>(1, GetActiveProcessorCount(ALL_PROCESSOR_GROUPS));
        do {
            ProcessInfo process;
            process.pid = static_cast<int>(entry.th32ProcessID);
            process.name = entry.szExeFile;
            process.observed_at = now;
            process.last_active = now;
            process.system_process = (process.pid == 0 || process.pid == 4);

            HANDLE handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ, FALSE, entry.th32ProcessID);
            if (handle != nullptr) {
                PROCESS_MEMORY_COUNTERS counters {};
                if (GetProcessMemoryInfo(handle, &counters, sizeof(counters))) {
                    process.rss_kb = counters.WorkingSetSize / 1024ULL;
                }

                FILETIME creation {};
                FILETIME exit_time {};
                FILETIME kernel {};
                FILETIME user {};
                if (GetProcessTimes(handle, &creation, &exit_time, &kernel, &user)) {
                    ULARGE_INTEGER kernel_time {};
                    kernel_time.LowPart = kernel.dwLowDateTime;
                    kernel_time.HighPart = kernel.dwHighDateTime;
                    ULARGE_INTEGER user_time {};
                    user_time.LowPart = user.dwLowDateTime;
                    user_time.HighPart = user.dwHighDateTime;
                    process.cpu_time_ticks = (kernel_time.QuadPart + user_time.QuadPart) / 10000ULL;

                    ULARGE_INTEGER creation_time {};
                    creation_time.LowPart = creation.dwLowDateTime;
                    creation_time.HighPart = creation.dwHighDateTime;
                    const auto age_ms = std::max(1.0, elapsed_since_filetime_ms(creation_time.QuadPart));
                    process.cpu_percent = (static_cast<double>(process.cpu_time_ticks) / age_ms) * 100.0 /
                                          static_cast<double>(cpu_count);
                }

                process.priority = priority_value_from_class(GetPriorityClass(handle));
                CloseHandle(handle);
            }

            processes.push_back(process);
        } while (Process32Next(snapshot, &entry));

        CloseHandle(snapshot);
        std::sort(processes.begin(), processes.end(),
                  [](const ProcessInfo& left, const ProcessInfo& right) { return left.rss_kb > right.rss_kb; });
        return processes;
    }

    MemoryStatus memory_status() override {
        MemoryStatus memory;
        MEMORYSTATUSEX status {};
        status.dwLength = sizeof(status);
        if (GlobalMemoryStatusEx(&status)) {
            memory.total_kb = status.ullTotalPhys / 1024ULL;
            memory.available_kb = status.ullAvailPhys / 1024ULL;
            memory.used_kb = memory.total_kb - memory.available_kb;
            memory.pressure_percent = static_cast<double>(status.dwMemoryLoad);
        }
        return memory;
    }

    bool suspend_process(const int pid, std::string& error) override {
        return for_each_thread(pid, [&](HANDLE thread) { return SuspendThread(thread) != static_cast<DWORD>(-1); }, error,
                               "suspend");
    }

    bool resume_process(const int pid, std::string& error) override {
        return for_each_thread(pid, [&](HANDLE thread) { return ResumeThread(thread) != static_cast<DWORD>(-1); }, error,
                               "resume");
    }

    bool kill_process(const int pid, std::string& error) override {
        HANDLE handle = OpenProcess(PROCESS_TERMINATE, FALSE, static_cast<DWORD>(pid));
        if (handle == nullptr) {
            error = "OpenProcess failed";
            return false;
        }
        const bool ok = TerminateProcess(handle, 1) != 0;
        if (!ok) {
            error = "TerminateProcess failed";
        }
        CloseHandle(handle);
        return ok;
    }

    bool change_priority(const int pid, const int priority, std::string& error) override {
        HANDLE handle = OpenProcess(PROCESS_SET_INFORMATION, FALSE, static_cast<DWORD>(pid));
        if (handle == nullptr) {
            error = "OpenProcess failed";
            return false;
        }

        DWORD priority_class = NORMAL_PRIORITY_CLASS;
        if (priority >= 13) {
            priority_class = HIGH_PRIORITY_CLASS;
        } else if (priority <= 5) {
            priority_class = IDLE_PRIORITY_CLASS;
        } else if (priority <= 7) {
            priority_class = BELOW_NORMAL_PRIORITY_CLASS;
        } else if (priority >= 10) {
            priority_class = ABOVE_NORMAL_PRIORITY_CLASS;
        }

        const bool ok = SetPriorityClass(handle, priority_class) != 0;
        if (!ok) {
            error = "SetPriorityClass failed";
        }
        CloseHandle(handle);
        return ok;
    }

    std::string platform_name() const override {
        return "Windows WinAPI";
    }

  private:
    static int priority_value_from_class(const DWORD priority_class) {
        switch (priority_class) {
        case IDLE_PRIORITY_CLASS:
            return 4;
        case BELOW_NORMAL_PRIORITY_CLASS:
            return 6;
        case ABOVE_NORMAL_PRIORITY_CLASS:
            return 10;
        case HIGH_PRIORITY_CLASS:
            return 13;
        default:
            return 8;
        }
    }

    static double elapsed_since_filetime_ms(const unsigned long long creation_filetime) {
        FILETIME now_filetime {};
        GetSystemTimeAsFileTime(&now_filetime);
        ULARGE_INTEGER now {};
        now.LowPart = now_filetime.dwLowDateTime;
        now.HighPart = now_filetime.dwHighDateTime;
        const auto elapsed_100ns = now.QuadPart - creation_filetime;
        return static_cast<double>(elapsed_100ns) / 10000.0;
    }

    template <typename Fn>
    static bool for_each_thread(const int pid, Fn&& fn, std::string& error, const std::string& action_name) {
        HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
        if (snapshot == INVALID_HANDLE_VALUE) {
            error = "thread snapshot failed";
            return false;
        }

        THREADENTRY32 thread_entry {};
        thread_entry.dwSize = sizeof(thread_entry);
        bool found = false;
        bool ok = true;

        if (Thread32First(snapshot, &thread_entry)) {
            do {
                if (thread_entry.th32OwnerProcessID != static_cast<DWORD>(pid)) {
                    continue;
                }
                found = true;
                HANDLE thread = OpenThread(THREAD_SUSPEND_RESUME, FALSE, thread_entry.th32ThreadID);
                if (thread == nullptr) {
                    ok = false;
                    error = "OpenThread failed";
                    break;
                }
                if (!fn(thread)) {
                    ok = false;
                    error = action_name + " thread operation failed";
                    CloseHandle(thread);
                    break;
                }
                CloseHandle(thread);
            } while (Thread32Next(snapshot, &thread_entry));
        }

        CloseHandle(snapshot);
        if (!found) {
            error = "no threads found for process";
            return false;
        }
        return ok;
    }
};

#endif

#if !defined(__linux__) && !defined(_WIN32)

class PosixFallbackProcessManager final : public ProcessManager {
  public:
    std::vector<ProcessInfo> list_processes() override {
        std::vector<ProcessInfo> processes;
#if defined(__APPLE__)
        const auto now = Clock::now();
        const long cpu_count = std::max(1L, sysconf(_SC_NPROCESSORS_ONLN));
        const auto now_seconds = std::chrono::duration_cast<std::chrono::seconds>(now.time_since_epoch()).count();

        std::vector<pid_t> pids(4096);
        int pid_count = proc_listallpids(pids.data(), static_cast<int>(pids.size() * sizeof(pid_t)));
        if (pid_count <= 0) {
            return processes;
        }
        if (pid_count > static_cast<int>(pids.size())) {
            pids.resize(static_cast<std::size_t>(pid_count));
            pid_count = proc_listallpids(pids.data(), static_cast<int>(pids.size() * sizeof(pid_t)));
        }

        for (int index = 0; index < pid_count; ++index) {
            const int pid = static_cast<int>(pids[static_cast<std::size_t>(index)]);
            if (pid <= 0) {
                continue;
            }

            proc_bsdinfo bsd_info {};
            if (proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, &bsd_info, sizeof(bsd_info)) != static_cast<int>(sizeof(bsd_info))) {
                continue;
            }

            ProcessInfo process;
            process.pid = pid;
            process.name = bsd_info.pbi_comm;
            process.owner = uid_to_username(bsd_info.pbi_ruid);
            process.priority = bsd_info.pbi_nice;
            process.observed_at = now;
            process.last_active = now;
            process.state = state_name(bsd_info.pbi_status);
            process.system_process =
                (process.pid == 1 || utils::to_lower(process.name) == "launchd" || utils::to_lower(process.name) == "kernel_task");

            char name_buffer[PROC_PIDPATHINFO_MAXSIZE] = {};
            if (proc_name(pid, name_buffer, sizeof(name_buffer)) > 0) {
                process.name = name_buffer;
            } else if (proc_pidpath(pid, name_buffer, sizeof(name_buffer)) > 0) {
                process.name = std::filesystem::path(name_buffer).filename().string();
            }

            proc_taskinfo task_info {};
            if (proc_pidinfo(pid, PROC_PIDTASKINFO, 0, &task_info, sizeof(task_info)) == static_cast<int>(sizeof(task_info))) {
                process.rss_kb = task_info.pti_resident_size / 1024ULL;
                const std::uint64_t total_cpu_ns = task_info.pti_total_user + task_info.pti_total_system;
                process.cpu_time_ticks = total_cpu_ns / 1000000ULL;

                const double start_time_seconds =
                    static_cast<double>(bsd_info.pbi_start_tvsec) + (static_cast<double>(bsd_info.pbi_start_tvusec) / 1000000.0);
                const double age_seconds =
                    std::max(1.0, static_cast<double>(now_seconds) - start_time_seconds);
                process.cpu_percent =
                    ((static_cast<double>(total_cpu_ns) / 1'000'000'000.0) / age_seconds) * 100.0 / static_cast<double>(cpu_count);
            }

            processes.push_back(process);
        }
#else
        FILE* handle = popen("ps -axo pid=,user=,comm=,rss=,%cpu=,pri=,stat=", "r");
        if (handle == nullptr) {
            return processes;
        }

        const auto now = Clock::now();
        char buffer[1024];
        while (fgets(buffer, sizeof(buffer), handle) != nullptr) {
            std::istringstream line(buffer);
            ProcessInfo process;
            process.observed_at = now;
            process.last_active = now;
            line >> process.pid >> process.owner >> process.name >> process.rss_kb >> process.cpu_percent >> process.priority >> process.state;
            if (line.fail() || process.pid <= 0) {
                continue;
            }
            process.system_process = (process.pid == 1 || utils::to_lower(process.name) == "launchd" ||
                                      utils::to_lower(process.name) == "kernel_task");
            processes.push_back(process);
        }
        pclose(handle);
#endif

        std::sort(processes.begin(), processes.end(),
                  [](const ProcessInfo& left, const ProcessInfo& right) { return left.rss_kb > right.rss_kb; });
        return processes;
    }

    MemoryStatus memory_status() override {
        MemoryStatus memory;
#if defined(__APPLE__)
        std::uint64_t total_memory = 0;
        size_t length = sizeof(total_memory);
        if (sysctlbyname("hw.memsize", &total_memory, &length, nullptr, 0) == 0) {
            memory.total_kb = total_memory / 1024ULL;
        }

        mach_msg_type_number_t count = HOST_VM_INFO64_COUNT;
        vm_statistics64_data_t vm_stats {};
        if (host_statistics64(mach_host_self(), HOST_VM_INFO64, reinterpret_cast<host_info64_t>(&vm_stats), &count) == KERN_SUCCESS) {
            const std::uint64_t page_size = static_cast<std::uint64_t>(sysconf(_SC_PAGESIZE));
            const std::uint64_t free_bytes = static_cast<std::uint64_t>(vm_stats.free_count + vm_stats.inactive_count) * page_size;
            memory.available_kb = free_bytes / 1024ULL;
        }
#endif
        if (memory.total_kb > memory.available_kb) {
            memory.used_kb = memory.total_kb - memory.available_kb;
            memory.pressure_percent = (static_cast<double>(memory.used_kb) / static_cast<double>(memory.total_kb)) * 100.0;
        }
        return memory;
    }

    bool suspend_process(const int pid, std::string& error) override {
        return signal_action(pid, SIGSTOP, error, "suspend");
    }

    bool resume_process(const int pid, std::string& error) override {
        return signal_action(pid, SIGCONT, error, "resume");
    }

    bool kill_process(const int pid, std::string& error) override {
        return signal_action(pid, SIGTERM, error, "kill");
    }

    bool change_priority(const int pid, const int priority, std::string& error) override {
        if (setpriority(PRIO_PROCESS, pid, priority) != 0) {
            error = "setpriority failed: " + std::string(std::strerror(errno));
            return false;
        }
        return true;
    }

    std::string platform_name() const override {
#if defined(__APPLE__)
        return "macOS libproc";
#else
        return "POSIX fallback";
#endif
    }

  private:
#if defined(__APPLE__)
    static std::string state_name(const int state) {
        switch (state) {
        case 1:
            return "idle";
        case 2:
            return "running";
        case 3:
            return "sleep";
        case 4:
            return "stop";
        case 5:
            return "zombie";
        default:
            return "unknown";
        }
    }
#endif

    static bool signal_action(const int pid, const int signal, std::string& error, const std::string& action_name) {
        if (::kill(pid, signal) != 0) {
            error = action_name + " failed: " + std::string(std::strerror(errno));
            return false;
        }
        return true;
    }
};

#endif

} // namespace

std::unique_ptr<ProcessManager> ProcessManager::create() {
#if defined(__linux__)
    return std::make_unique<LinuxProcessManager>();
#elif defined(_WIN32)
    return std::make_unique<WindowsProcessManager>();
#else
    return std::make_unique<PosixFallbackProcessManager>();
#endif
}

} // namespace amoe
