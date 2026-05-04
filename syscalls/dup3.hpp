#pragma once
#include "../core/syscall.hpp"
#include "../core/fd_tracker.hpp"
#include "../core/process.hpp"
#include "../core/register.hpp"
#include "../core/state.hpp"
#include <sys/syscall.h>
struct Dup3Syscall : Syscall<Dup3Syscall,
                             SYS_dup3,
                             IntArg,
                             IntArg,
                             IntArg>
{
    static const char *name() { return "dup3"; }

    static void exit(pid_t pid, ptrace_syscall_info *info)
    {
        int oldfd = syscall_state[pid].args[0];
        int newfd = syscall_state[pid].args[1];

        if (info->exit.rval < 0)
            return;

        pid_t tgid = get_tgid(pid);

        auto &fds = fd_table[tgid];

        auto it = fds.find(oldfd);
        if (it == fds.end())
            return;

        fds[newfd] = it->second;
    }
};

static Register<Dup3Syscall> reg_dup3;