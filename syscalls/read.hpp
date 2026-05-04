#pragma once
#include <cstdio>
#include "../core/syscall.hpp"
#include "../core/fd_tracker.hpp"
#include "../core/process.hpp"
#include "../core/register.hpp"
#include "../core/state.hpp"
#include "../core/config.hpp"
#include "../core/rules.hpp"
#include <cctype>
#include <vector>
#include <sys/syscall.h>
struct ReadSyscall : Syscall<ReadSyscall,
                             SYS_read,
                             IntArg,
                             PtrArg,
                             SizeArg>
{
    static void entry(pid_t pid, ptrace_syscall_info *)
    {
        pid_t tgid = get_tgid(pid);
        int fd = syscall_state[pid].args[0];

        auto it_pid = fd_table.find(tgid);
        if (it_pid == fd_table.end())
            return;

        auto it_fd = it_pid->second.find(fd);
        if (it_fd == it_pid->second.end())
            return;

        auto obj = it_fd->second;

        if (obj->type == FD_FILE)
            if (!rules::apply_file_rule(pid, obj->label, "read"))
                return;
    }
    static const char *name() { return "read"; }

    static void exit(pid_t pid, ptrace_syscall_info *info)
    {
        if (info->exit.rval < 0)
            return;
        pid_t tgid = get_tgid(pid);

        int fd = syscall_state[pid].args[0];
        long buf = syscall_state[pid].args[1];

        auto it_pid = fd_table.find(tgid);
        if (it_pid == fd_table.end())
            return;

        auto it_fd = it_pid->second.find(fd);
        if (it_fd == it_pid->second.end())
            return;

        auto obj = it_fd->second;

        if (obj->type == FD_FILE)
            LOG(1, "[FILE] read: %s\n", obj->label.c_str());
        else if (obj->type == FD_SOCKET)
            LOG(1, "[NET] read: %s\n", obj->label.c_str());
        else
            LOG(1, "[FD] read: %s\n", obj->label.c_str());
        if (LOG_LEVEL >= 1 && info->exit.rval > 0)
        {
            size_t size = static_cast<size_t>(info->exit.rval);

            if (LOG_LEVEL == 1 && size > 256)
                size = 256;

            if (size == 0)
                return;

            std::vector<char> data(size, 0);

            if (read_child_memory(pid, data.data(), buf, size) > 0)
            {
                LOG(2, "        content: \"");
                for (size_t i = 0; i < size; i++)
                {
                    if (isprint(static_cast<unsigned char>(data[i])))
                        fputc(data[i], LOG_FILE);
                    else
                        fputc('.', LOG_FILE);
                }
                LOG(2, "\"\n");
            }
        }
    }
};

static Register<ReadSyscall> reg_read;