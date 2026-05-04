#pragma once
#include <cstdio>
#include "../core/syscall.hpp"
#include "../core/fd_tracker.hpp"
#include "../core/process.hpp"
#include "../core/register.hpp"
#include "../core/state.hpp"
#include "../core/config.hpp"
#include <sys/socket.h>
#include <sys/uio.h>
#include <vector>
#include <cctype>
#include <sys/syscall.h>
struct RecvMsgSyscall : Syscall<RecvMsgSyscall,
                                SYS_recvmsg,
                                IntArg,
                                PtrArg,
                                IntArg>
{
    static const char *name() { return "recvmsg"; }

    static void exit(pid_t pid, ptrace_syscall_info *info)
    {
        long ret = info->exit.rval;
        if (ret <= 0) return;

        int fd = syscall_state[pid].args[0];
        long msg_ptr = syscall_state[pid].args[1];

        pid_t tgid = get_tgid(pid);

        auto it = fd_table[tgid].find(fd);
        if (it == fd_table[tgid].end())
            return;

        auto obj = it->second;

        LOG(1, "[NET] recvmsg: %s\n", obj->label.c_str());

        if (LOG_LEVEL < 1) return;

        struct msghdr msg{};
        if (read_child_memory(pid, &msg, msg_ptr, sizeof(msg)) <= 0)
            return;

        

        for (size_t i = 0; i < msg.msg_iovlen; i++)
        {
            struct iovec iov;
            if (read_child_memory(pid, &iov,
                (unsigned long long)msg.msg_iov + i * sizeof(iov),
                sizeof(iov)) <= 0)
                continue;

            size_t size = iov.iov_len;
            if (LOG_LEVEL == 1 && size > 256)
                size = 256;

            std::vector<char> data(size);

            if (read_child_memory(pid, data.data(),
                                  (unsigned long long)iov.iov_base,
                                  size) > 0)
            {
                LOG(2, "        chunk: \"");
                for (char c : data)
                    fputc(isprint((unsigned char)c) ? c : '.',LOG_FILE);
                LOG(2, "\"\n");
            }
        }
    }
};

static Register<RecvMsgSyscall> reg_recvmsg;