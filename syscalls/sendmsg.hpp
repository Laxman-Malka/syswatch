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
struct SendMsgSyscall : Syscall<SendMsgSyscall,
                                SYS_sendmsg,
                                IntArg,
                                PtrArg,
                                IntArg>
{
    static const char *name() { return "sendmsg"; }

    static void exit(pid_t pid, ptrace_syscall_info *info)
    {
        long ret = info->exit.rval;
        if (ret <= 0)
            return;

        int fd = syscall_state[pid].args[0];
        unsigned long long msg_ptr = syscall_state[pid].args[1];

        pid_t tgid = get_tgid(pid);

        auto it_pid = fd_table.find(tgid);
        if (it_pid == fd_table.end())
            return;

        auto it_fd = it_pid->second.find(fd);
        if (it_fd == it_pid->second.end())
            return;

        auto obj = it_fd->second;

        LOG(1, "[NET] sendmsg: %s\n", obj->label.c_str());

        if (LOG_LEVEL < 1)
            return;

        struct msghdr msg{};
        if (read_child_memory(pid, &msg, msg_ptr, sizeof(msg)) <= 0)
            return;

        // 🔥 iterate over iovecs
        for (size_t i = 0; i < msg.msg_iovlen; i++)
        {
            struct iovec iov{};

            unsigned long long iov_addr =
                (unsigned long long)msg.msg_iov + i * sizeof(struct iovec);

            if (read_child_memory(pid, &iov, iov_addr, sizeof(iov)) <= 0)
                continue;

            size_t size = iov.iov_len;

            // truncate at lower verbosity
            if (LOG_LEVEL == 1 && size > 256)
                size = 256;

            if (size == 0)
                continue;

            std::vector<char> data(size);

            if (read_child_memory(pid,
                                  data.data(),
                                  (unsigned long long)iov.iov_base,
                                  size) <= 0)
                continue;

            LOG(2, "        chunk[%zu]: \"", i);

            for (size_t j = 0; j < size; j++)
            {
                unsigned char c = data[j];
                fputc(isprint(c) ? c : '.',LOG_FILE);
            }

            LOG(2, "\"\n");
        }
    }
};

static Register<SendMsgSyscall> reg_sendmsg;