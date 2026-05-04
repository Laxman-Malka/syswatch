#pragma once
#include "../core/syscall.hpp"
#include "../core/fd_tracker.hpp"
#include "../core/process.hpp"
#include "../core/register.hpp"
#include "../core/state.hpp"
#include <sys/syscall.h>
struct DupSyscall : Syscall<DupSyscall,
                            SYS_dup,
                            IntArg>
{
    static const char *name() { return "dup"; }

    static void exit(pid_t pid, ptrace_syscall_info *info)
    {
        int oldfd = syscall_state[pid].args[0];
        int newfd = info->exit.rval;

        if (newfd < 0)
            return;

        pid_t tgid = get_tgid(pid);

        auto &fds = fd_table[tgid];

        auto it = fds.find(oldfd);
        if (it == fds.end())
            return;

        // 🔥 alias SAME object
        fds[newfd] = it->second;
    }
};

static Register<DupSyscall> reg_dup;