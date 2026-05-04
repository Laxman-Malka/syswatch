#pragma once
#include "../core/syscall.hpp"
#include "../core/fd_tracker.hpp"
#include "../core/process.hpp"
#include "../core/register.hpp"
#include <sys/syscall.h>
struct SocketPairSyscall : Syscall<SocketPairSyscall,
                                   SYS_socketpair,
                                   IntArg,
                                   IntArg,
                                   IntArg,
                                   PtrArg>
{
    static const char *name() { return "socketpair"; }

    static void exit(pid_t pid, ptrace_syscall_info *info)
    {
        if (info->exit.rval < 0)
            return;

        int fds[2];

        if (read_child_memory(pid, fds,
                              info->entry.args[3],
                              sizeof(fds)) <= 0)
            return;

        pid_t tgid = get_tgid(pid);

        // 🔥 SAME object for both ends
        auto obj = std::make_shared<FDObject>();
        obj->type = FD_SOCKET;
        obj->label = "socketpair";
        obj->active = true;

        fd_table[tgid][fds[0]] = obj;
        fd_table[tgid][fds[1]] = obj;
    }
};

static Register<SocketPairSyscall> reg_socketpair;