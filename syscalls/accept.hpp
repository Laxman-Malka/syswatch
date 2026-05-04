#include <cstdio>
#pragma once
#include "../core/syscall.hpp"
#include "../core/fd_tracker.hpp"
#include "../core/process.hpp"
#include "../core/register.hpp"
#include "../core/state.hpp"
#include "../core/net_utils.hpp"
#include <sys/syscall.h>
struct AcceptSyscall : Syscall<AcceptSyscall,
                               SYS_accept,
                               IntArg,
                               PtrArg,
                               PtrArg>
{
    static const char *name() { return "accept"; }

    static void exit(pid_t pid, ptrace_syscall_info *info)
    {
        long newfd = info->exit.rval;
        if (newfd < 0)
            return;

        pid_t tgid = get_tgid(pid);

        auto obj = std::make_shared<FDObject>();
        obj->type = FD_SOCKET;
        obj->active = true;

        unsigned long long addr_ptr = syscall_state[pid].args[1];

        if (addr_ptr != 0)
        {
            char buffer[128];

            if (read_child_memory(pid, buffer, addr_ptr, sizeof(buffer)) > 0)
            {
                auto parsed = parse_sockaddr(buffer);
                if (parsed != "unknown")
                    obj->label = parsed;
                LOG(1, "[NET] accept: %s\n", obj->label.c_str());
            }
            else
            {
                obj->label = "socket(accepted)";
            }
        }
        else
        {
            obj->label = "socket(accepted)";
        }

        fd_table[tgid][newfd] = obj;
    }
};

static Register<AcceptSyscall> reg_accept;