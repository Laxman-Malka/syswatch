#pragma once
#include "../core/syscall.hpp"
#include "../core/fd_tracker.hpp"
#include "../core/process.hpp"
#include "../core/register.hpp"
#include <sys/syscall.h>
struct Pipe2Syscall : Syscall<Pipe2Syscall,
                              SYS_pipe2,
                              PtrArg,
                              IntArg>
{
    static const char *name() { return "pipe2"; }

    static void exit(pid_t pid, ptrace_syscall_info *info)
    {
        int fds[2];

        if (read_child_memory(pid, fds, info->entry.args[0], sizeof(fds)) <= 0)
            return;

        pid_t tgid = get_tgid(pid);

        auto read_obj = std::make_shared<FDObject>();
        read_obj->type = FD_PIPE;
        read_obj->label = "pipe(read)";
        read_obj->active = true;

        auto write_obj = std::make_shared<FDObject>();
        write_obj->type = FD_PIPE;
        write_obj->label = "pipe(write)";
        write_obj->active = true;

        fd_table[tgid][fds[0]] = read_obj;
        fd_table[tgid][fds[1]] = write_obj;
    }
};

static Register<Pipe2Syscall> reg_pipe2;