#pragma once
#include "../core/syscall.hpp"
#include "../core/register.hpp"
#include "../core/types.hpp"
#include <sys/syscall.h>

struct ExecveSyscall : Syscall<ExecveSyscall,
                               SYS_execve,
                               CStringArg,
                               PtrArg,
                               PtrArg>
{
    static const char *name() { return "execve"; }
};

static Register<ExecveSyscall> reg_execve;