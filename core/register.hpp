#pragma once
#include "dispatcher.hpp"
#include "concepts.hpp"
template<SyscallType S>
struct Register {
    Register() {
        syscall_table[S::number].entry = &S::entry;
        syscall_table[S::number].exit  = &S::exit;
    }
};