#pragma once
#include <cstdio>
#include "../core/syscall.hpp"
#include "../core/fd_tracker.hpp"
#include "../core/process.hpp"
#include "../core/register.hpp"
#include "../core/state.hpp"
#include "../core/net_utils.hpp"
#include "../core/rules.hpp"
#include <sys/user.h>
#include <sys/syscall.h>

struct ConnectSyscall : Syscall<ConnectSyscall,
                                SYS_connect,
                                IntArg,
                                PtrArg,
                                IntArg>
{
    static void entry(pid_t pid, ptrace_syscall_info *info)
    {
        unsigned long long addr_ptr = info->entry.args[1];

        if (addr_ptr == 0)
            return;

        char buffer[128];

        if (read_child_memory(pid, buffer, addr_ptr, sizeof(buffer)) <= 0)
            return;

        auto parsed = parse_sockaddr(buffer);

        if (parsed != "unknown")
            rules::apply_network_rule(pid, parsed, "connect");
    }
    static const char *name() { return "connect"; }

    static void exit(pid_t pid, ptrace_syscall_info *info)
    {
        if (info->exit.rval < 0)
            return;
        int fd = syscall_state[pid].args[0];
        unsigned long long addr_ptr = syscall_state[pid].args[1];
        pid_t tgid = get_tgid(pid);

        auto it_pid = fd_table.find(tgid);
        if (it_pid == fd_table.end())
            return;

        auto it_fd = it_pid->second.find(fd);
        if (it_fd == it_pid->second.end())
            return;

        auto obj = it_fd->second;

        // 🔥 read sockaddr
        char buffer[128];

        if (read_child_memory(pid, buffer, addr_ptr, sizeof(buffer)) <= 0)
            return;

        // 🔥 update object first
        obj->type = FD_SOCKET;
        auto parsed = parse_sockaddr(buffer);
        if (parsed != "unknown")
            obj->label = parsed;

        LOG(1, "[NET] connect: %s\n", obj->label.c_str());
    }
};

static Register<ConnectSyscall> reg_connect;