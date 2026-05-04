#pragma once
#include <cstdio>
#include "../core/syscall.hpp"
#include "../core/register.hpp"
#include "../core/types.hpp"
#include "../core/fd_tracker.hpp"
#include "../core/process.hpp"
#include "../core/rules.hpp"
#include <unordered_map>
#include <sys/syscall.h>
// 🔥 cache path per process
inline std::unordered_map<pid_t, std::string> open_path_cache;

struct OpenSyscall : Syscall<OpenSyscall,
                             SYS_open,
                             CStringArg,
                             IntArg,
                             IntArg>
{
    static const char *name() { return "open"; }

    // 🔥 ENTRY: capture path safely
    static void entry(pid_t pid, ptrace_syscall_info *info)
    {
        char path[256] = {0};

        read_child_memory(pid, path, info->entry.args[0], sizeof(path));

        pid_t tgid = get_tgid(pid);

        open_path_cache[tgid] = std::string(path);

        if (!rules::apply_file_rule(pid, open_path_cache[tgid], "open"))
            return;
    }

    // 🔥 EXIT: use cached path
    static void exit(pid_t pid, ptrace_syscall_info *info)
    {
        long fd = info->exit.rval;
        if (fd < 0)
            return;

        pid_t tgid = get_tgid(pid);

        auto it = open_path_cache.find(tgid);
        if (it == open_path_cache.end())
            return;

        const std::string &path = it->second;

        auto obj = std::make_shared<FDObject>();
        obj->type = FD_FILE;
        obj->label = path;
        obj->active = true;

        fd_table[tgid][fd] = obj;

        LOG(1, "[FILE] open: %s\n", path.c_str());
        open_path_cache.erase(it);
    }
};

static Register<OpenSyscall> reg_open;