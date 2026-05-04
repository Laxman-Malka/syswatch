#pragma once
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <linux/ptrace.h>
#include "state.hpp"
#include <cstring>
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