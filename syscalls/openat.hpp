#include <cstdio>
#pragma once
#include "../core/syscall.hpp"
#include "../core/process.hpp"
#include "../core/fd_tracker.hpp"
#include "../core/types.hpp"
#include "../core/register.hpp"
#include "../core/rules.hpp"
#include <unordered_map>
#include <sys/syscall.h>
inline std::unordered_map<pid_t, std::string> openat_path_cache;

struct OpenAtSyscall : Syscall<OpenAtSyscall,
                               SYS_openat,
                               IntArg,
                               CStringArg,
                               IntArg,
                               IntArg>
{
    static void entry(pid_t pid, ptrace_syscall_info *info)
    {
        char path[256] = {0};

        read_child_memory(pid, path, info->entry.args[1], sizeof(path));

        pid_t tgid = get_tgid(pid);

        openat_path_cache[tgid] = std::string(path);

        if (!rules::apply_file_rule(pid, openat_path_cache[tgid], "open"))
            return;
    }

    static const char *name() { return "openat"; }

    static void exit(pid_t pid, ptrace_syscall_info *info)
    {
        long fd = info->exit.rval;
        if (fd < 0)
            return;

        pid_t tgid = get_tgid(pid);

        const std::string &path = openat_path_cache[tgid];

        auto obj = std::make_shared<FDObject>();
        obj->type = FD_FILE;
        obj->label = path;
        obj->active = true;

        fd_table[tgid][fd] = obj;

        LOG(1, "[FILE] open: %s\n", path.c_str());
        openat_path_cache.erase(tgid);
    }
};

static Register<OpenAtSyscall> reg_openat;