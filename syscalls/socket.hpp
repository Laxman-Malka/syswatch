#pragma once
#include "../core/syscall.hpp"
#include "../core/fd_tracker.hpp"
#include "../core/process.hpp"
#include "../core/register.hpp"
#include <sys/syscall.h>
struct SocketSyscall : Syscall<SocketSyscall,
                               SYS_socket,
                               IntArg,
                               IntArg,
                               IntArg>
{
    static const char *name() { return "socket"; }

    static void exit(pid_t pid, ptrace_syscall_info *info)
    {
        long fd = info->exit.rval;
        if (fd < 0)
            return;

        pid_t tgid = get_tgid(pid);

        auto obj = std::make_shared<FDObject>();
        obj->type = FD_SOCKET;
        obj->label = "socket(unconnected)";
        obj->active = true;

        fd_table[tgid][fd] = obj;
    }
};

static Register<SocketSyscall> reg_socket;