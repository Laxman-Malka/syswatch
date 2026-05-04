#pragma once
#include <unordered_map>
#include <sys/types.h>

struct SyscallState {
    long args[6];
};

inline std::unordered_map<pid_t, SyscallState> syscall_state;