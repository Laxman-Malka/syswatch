#pragma once
#include <cstdio>
#include <linux/ptrace.h>
#include "types.hpp"
#include<cstdio>
#include "concepts.hpp"
#include "config.hpp"
// PRIMARY TEMPLATE (must include variadic args!)
template<size_t I, typename... Args>
struct ArgPrinter;

// BASE CASE (no args left)
template<size_t I>
struct ArgPrinter<I> {
    static void print(pid_t, ptrace_syscall_info*) {}
};

// RECURSIVE CASE
template<size_t I, ArgType First, ArgType... Rest>
struct ArgPrinter<I, First, Rest...> {
    static void print(pid_t pid, ptrace_syscall_info* info) {
        First::print(pid, info, I);

        if constexpr (sizeof...(Rest) > 0) {
            fprintf(LOG_FILE, ", ");
            ArgPrinter<I + 1, Rest...>::print(pid, info);
        }
    }
};