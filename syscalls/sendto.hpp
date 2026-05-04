#include <cstdio>
#pragma once
#include "../core/syscall.hpp"
#include "../core/fd_tracker.hpp"
#include "../core/process.hpp"
#include "../core/register.hpp"
#include "../core/state.hpp"
#include "../core/config.hpp"
#include "../core/net_utils.hpp"

#include <sys/syscall.h>
#include <vector>
#include <cctype>

struct SendToSyscall : Syscall<SendToSyscall,
                               SYS_sendto,
                               IntArg,
                               PtrArg,
                               SizeArg,
                               IntArg,
                               PtrArg,
                               IntArg>
{
    static const char *name() { return "sendto"; }

    static void exit(pid_t pid, ptrace_syscall_info *info)
    {
        long ret = info->exit.rval;
        if (ret <= 0)
            return;

        int fd = syscall_state[pid].args[0];
        unsigned long long buf_ptr = syscall_state[pid].args[1];
        unsigned long long addr_ptr = syscall_state[pid].args[4];

        pid_t tgid = get_tgid(pid);

        auto it_pid = fd_table.find(tgid);
        if (it_pid == fd_table.end())
            return;

        auto it_fd = it_pid->second.find(fd);
        if (it_fd == it_pid->second.end())
            return;

        auto obj = it_fd->second;

        // 🔥 prefer explicit destination if present
        std::string target = obj->label;

        if (addr_ptr != 0)
        {
            char buffer[128];

            if (read_child_memory(pid, buffer, addr_ptr, sizeof(buffer)) > 0){
                auto parsed = parse_sockaddr(buffer);
                if (parsed != "unknown")
                    target = parsed;
            }
        }

        LOG(1, "[NET] sendto: %s\n", target.c_str());

        // 🔥 content
        if (LOG_LEVEL >= 1)
        {
            size_t size = (size_t)ret;

            if (LOG_LEVEL == 1 && size > 256)
                size = 256;

            if (size == 0)
                return;

            std::vector<char> data(size);

            if (read_child_memory(pid, data.data(), buf_ptr, size) > 0)
            {
                LOG(2, "        content: \"");

                for (unsigned char c : data)
                    fputc(isprint(c) ? c : '.',LOG_FILE);

                LOG(2, "\"\n");
            }
        }
    }
};

static Register<SendToSyscall> reg_sendto;