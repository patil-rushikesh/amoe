cmake_minimum_required(VERSION 3.16)
project(amoe LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

add_executable(amoe
    main.cpp
    common/utils.cpp
    config/config.cpp
    system/process_manager.cpp
    algorithms/fcfs.cpp
    algorithms/lru.cpp
    algorithms/optimal.cpp
    algorithms/hybrid.cpp
    monitor/tracker.cpp
    decision/engine.cpp
    security/safety.cpp
    security/permissions.cpp
    audit/logger.cpp
    audit/audit_reader.cpp
    ui/cli.cpp
)

target_include_directories(amoe PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})

if (WIN32)
    target_link_libraries(amoe PRIVATE psapi advapi32)
endif ()
