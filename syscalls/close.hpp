#include <cstdio>
#pragma once
#include "../core/syscall.hpp"
#include "../core/fd_tracker.hpp"
#include "../core/process.hpp"
#include "../core/register.hpp"
#include "../core/state.hpp"
#include <sys/syscall.h>
struct CloseSyscall : Syscall<CloseSyscall,
                              SYS_close,
                              IntArg>
{
    static const char *name() { return "close"; }

    static void exit(pid_t pid, ptrace_syscall_info *)
    {
        pid_t tgid = get_tgid(pid);

        int fd = syscall_state[pid].args[0];

        auto it_pid = fd_table.find(tgid);
        if (it_pid == fd_table.end())
        {
            LOG(1, "[FD] close: unknown fd=%d\n", fd);
            return;
        }

        auto &fds = it_pid->second;

        auto it_fd = fds.find(fd);
        if (it_fd != fds.end())
        {
            auto obj = it_fd->second;

            if (obj->type == FD_FILE)
                LOG(1, "[FILE] close: %s\n", obj->label.c_str());
            else if (obj->type == FD_SOCKET)
                LOG(1, "[NET] close: %s\n", obj->label.c_str());
            else
                LOG(1, "[FD] close: %s\n", obj->label.c_str());

            fds.erase(it_fd);
        }
        else
        {
            // ✅ cleaner fallback
            LOG(1, "[FD] close: unknown fd=%d\n", fd);
        }
    }
};

static Register<CloseSyscall> reg_close;