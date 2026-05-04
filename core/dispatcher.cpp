#include "dispatcher.hpp"
#include <stdio.h>
#include <cstring>
#include <sys/user.h>
#include "rules.hpp"

int last_syscall[MAX_PID] = {0};

void dispatch_entry(pid_t pid, ptrace_syscall_info *info)
{
    int nr = info->entry.nr;

    last_syscall[pid] = nr;

    memcpy(syscall_state[pid].args,
           info->entry.args,
           sizeof(info->entry.args));

    if (nr >= 0 && nr < 512 && syscall_table[nr].entry)
        syscall_table[nr].entry(pid, info);
}
void dispatch_exit(pid_t pid, ptrace_syscall_info *info)
{
    int nr = last_syscall[pid];

    if (nr >= 0 && nr < 512 && syscall_table[nr].exit)
        syscall_table[nr].exit(pid, info);
}