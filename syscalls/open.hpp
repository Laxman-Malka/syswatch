#pragma once
#include "../core/syscall.hpp"
#include "../core/register.hpp"
#include "../core/types.hpp"

struct OpenSyscall : Syscall<OpenSyscall,
    2,
    CStringArg,
    IntArg,
    IntArg
> {
    static const char* name() { return "open"; }
};

static Register<OpenSyscall> reg_open;
