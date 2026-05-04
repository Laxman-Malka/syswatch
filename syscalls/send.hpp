#include <cstdio>
#pragma once
#include "../core/syscall.hpp"
#include "../core/fd_tracker.hpp"
#include "../core/process.hpp"
#include "../core/register.hpp"
#include "../core/state.hpp"
#include "../core/config.hpp"

#include <sys/syscall.h>
#include <vector>
#include <cctype>

struct SendSyscall : Syscall<SendSyscall,
                             SYS_sendto,   // same syscall number on x86_64
                             IntArg,
                             PtrArg,
                             SizeArg,
                             IntArg>
{
    static const char *name() { return "send"; }

    static void exit(pid_t pid, ptrace_syscall_info *info)
    {
        long ret = info->exit.rval;
        if (ret <= 0)
            return;

        int fd = syscall_state[pid].args[0];
        unsigned long long buf = syscall_state[pid].args[1];

        pid_t tgid = get_tgid(pid);

        auto it_pid = fd_table.find(tgid);
        if (it_pid == fd_table.end())
            return;

        auto it_fd = it_pid->second.find(fd);
        if (it_fd == it_pid->second.end())
            return;

        auto obj = it_fd->second;

        LOG(1, "[NET] send: %s\n", obj->label.c_str());

        if (LOG_LEVEL >= 1)
        {
            size_t size = (size_t)ret;

            if (LOG_LEVEL == 1 && size > 256)
                size = 256;

            if (size == 0)
                return;

            std::vector<char> data(size);

            if (read_child_memory(pid, data.data(), buf, size) > 0)
            {
                LOG(2, "        content: \"");

                for (unsigned char c : data)
                    fputc(isprint(c) ? c : '.',LOG_FILE);

                LOG(2, "\"\n");
            }
        }
    }
};

static Register<SendSyscall> reg_send;