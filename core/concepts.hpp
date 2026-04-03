#pragma once
#include <linux/ptrace.h>
#include <unistd.h>
#include <concepts>

template<typename T>
concept ArgType = requires(pid_t pid, ptrace_syscall_info* info, size_t i) {
    { T::print(pid, info, i) } -> std::same_as<void>;
};
template<typename T>
concept SyscallType = requires(pid_t pid, ptrace_syscall_info* info) {
    { T::name() } -> std::convertible_to<const char*>;
    { T::number } -> std::convertible_to<int>;
    { T::entry(pid, info) } -> std::same_as<void>;
    { T::exit(pid, info) } -> std::same_as<void>;
};