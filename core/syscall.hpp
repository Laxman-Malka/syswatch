#pragma once
#include <linux/ptrace.h>
#include <stdio.h>

#include "printer.hpp"
#include "concepts.hpp"
#include "config.hpp"
#include "rules.hpp"

template<typename Derived, int NR, ArgType... Args>
struct Syscall {
    static constexpr int number = NR;

    static void entry(pid_t pid, ptrace_syscall_info* info) {
        if (!rules::apply_syscall_rule(pid, Derived::name()))
            return;

        if (LOG_LEVEL < 3)
            return;

        LOG(3, "[pid %d] %s(", pid, Derived::name());
        ArgPrinter<0, Args...>::print(pid, info);
        LOG(3, ")\n");
    }

    static void exit(pid_t, ptrace_syscall_info*) {}
};