#pragma once
#include <linux/ptrace.h>
#include <unistd.h>

using EntryFn = void(*)(pid_t, ptrace_syscall_info*);
using ExitFn  = void(*)(pid_t, ptrace_syscall_info*);

struct SysEntry {
    EntryFn entry;
    ExitFn  exit;
};

inline SysEntry syscall_table[512]={};

// store last syscall per pid
constexpr int MAX_PID = 65536;
extern int last_syscall[MAX_PID];

// dispatch
void dispatch_entry(pid_t pid, ptrace_syscall_info* info);
void dispatch_exit(pid_t pid, ptrace_syscall_info* info);