#include "dispatcher.hpp"
#include <stdio.h>

int last_syscall[MAX_PID] = {0};

void dispatch_entry(pid_t pid, ptrace_syscall_info* info) {
    int nr = info->entry.nr;
    if (pid < MAX_PID)
        last_syscall[pid] = nr;

    if (nr < 512 && syscall_table[nr].entry) {
        syscall_table[nr].entry(pid, info);
    } else {
        printf("[pid %d] unknown(%d", pid, nr);
        for (int i = 0; i < 3; i++)
            printf(", %llu", (unsigned long long)info->entry.args[i]);
        printf(")\n");
    }
}

void dispatch_exit(pid_t pid, ptrace_syscall_info* info) {
    int nr = -1;
    if (pid < MAX_PID)
        nr = last_syscall[pid];

    if (nr >= 0 && nr < 512 && syscall_table[nr].exit) {
        syscall_table[nr].exit(pid, info);
    }
}