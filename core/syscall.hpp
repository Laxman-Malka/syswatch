#pragma once
#include <linux/ptrace.h>
#include <stdio.h>
#include "printer.hpp"
#include "concepts.hpp"
template<typename Derived ,int NR, ArgType... Args>
struct Syscall {
    static constexpr int number = NR;

    static void entry(pid_t pid, ptrace_syscall_info* info) {
        printf("[pid %d] %s(", pid, Derived::name());
        ArgPrinter<0, Args...>::print(pid, info);
        printf(")\n");
    }

    static void exit(pid_t, ptrace_syscall_info*) {}
};