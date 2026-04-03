#pragma once
#include "../core/types.hpp"
#include "../core/syscall.hpp"
#include "../core/register.hpp"

struct WriteSyscall : Syscall<WriteSyscall,
    1,
    IntArg,
    BufferArg<2>,
    SizeArg
> {
    static const char* name() { return "write"; }
};
static Register<WriteSyscall> reg_write;