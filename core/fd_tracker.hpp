#pragma once
#include <unordered_map>
#include <string>
#include <memory>
#include <sys/types.h>

enum FDType {
    FD_FILE,
    FD_SOCKET,
    FD_PIPE,
    FD_UNKNOWN
};

struct FDObject {
    FDType type = FD_UNKNOWN;
    bool active = true;
    std::string label;   // path, endpoint, or pipe name
};

using FDObjectPtr = std::shared_ptr<FDObject>;

inline std::unordered_map<pid_t, std::unordered_map<int, FDObjectPtr>> fd_table;