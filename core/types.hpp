#pragma once
#include <cstdio>
#include <stdio.h>
#include <sys/ptrace.h>
#include <string.h>
#include<sys/types.h>
#include<vector>
#include<cstdlib>
#include <sys/uio.h>        // process_vm_readv, iovec
#include <linux/ptrace.h>  // ptrace_syscall_info
#include <unistd.h>        // pid_t
#include <vector>          // std::vector
#include <cstdio>          // printf
#include <cctype>          // isprint
#include <algorithm>
#define PTRACE(req, ...) ptrace(static_cast<__ptrace_request>(req), __VA_ARGS__)
#include <sys/uio.h>
#include <unistd.h>
#include <cerrno>
#include <cstddef>

// returns number of bytes actually read
inline ssize_t read_child_memory(
    pid_t pid,
    void* local_buf,
    unsigned long long remote_addr,
    size_t len
) {
    struct iovec local {
        .iov_base = local_buf,
        .iov_len  = len
    };

    struct iovec remote {
        .iov_base = (void*)remote_addr,
        .iov_len  = len
    };

    return process_vm_readv(pid, &local, 1, &remote, 1, 0);
}

// ─── BASIC TYPES ───

struct IntArg {
    static void print(pid_t, ptrace_syscall_info* info, size_t i) {
        fprintf(LOG_FILE, "%lld", (long long)info->entry.args[i]);
    }
};



struct SizeArg {
    static void print(pid_t, ptrace_syscall_info* info, size_t i) {
        fprintf(LOG_FILE, "%llu", (unsigned long long)info->entry.args[i]);
    }
};

struct PtrArg {
    static void print(pid_t, ptrace_syscall_info* info,size_t i) {
        fprintf(LOG_FILE, "0x%llx", static_cast<unsigned long long>(info->entry.args[i]));
    }
};

// ─── STRING TYPE (important) ───

struct CStringArg {
    static constexpr size_t CHUNK = 256;
    static constexpr size_t MAX_TOTAL = 1 << 20;

    static void print(pid_t pid, ptrace_syscall_info* info, size_t i) {
        unsigned long long addr = info->entry.args[i];

        if (!addr) {
            fprintf(LOG_FILE, "NULL");
            return;
        }

        std::vector<char> buffer;
        buffer.reserve(CHUNK);

        size_t offset = 0;

        while (offset < MAX_TOTAL) {
            char temp[CHUNK];

            ssize_t n = read_child_memory(pid, temp, addr + offset, CHUNK);

            if (n <= 0) {
                if (buffer.empty()) {
                    fprintf(LOG_FILE, "<invalid ptr>");
                    return;
                }
                break;
            }

            for (ssize_t j = 0; j < n; j++) {
                char c = temp[j];
                buffer.push_back(c);

                if (c == '\0') {
                    print_sanitized(buffer.data(), buffer.size() - 1);
                    return;
                }
            }

            offset += n;
        }

        print_sanitized(buffer.data(), buffer.size());
        fprintf(LOG_FILE, "...");
    }

private:
    static void print_sanitized(const char* data, size_t len) {
        fprintf(LOG_FILE, "\"");

        for (size_t k = 0; k < len; k++) {
            unsigned char c = data[k];

            switch (c) {
                case '\n': fprintf(LOG_FILE, "\\n"); break;
                case '\t': fprintf(LOG_FILE, "\\t"); break;
                case '\r': fprintf(LOG_FILE, "\\r"); break;
                case '\\': fprintf(LOG_FILE, "\\\\"); break;
                case '"':  fprintf(LOG_FILE, "\\\""); break;

                default:
                    if (isprint(c))
                        fputc(c,LOG_FILE);
                    else
                        fprintf(LOG_FILE, "\\x%02x", c);
            }
        }

        fprintf(LOG_FILE, "\"");
    }
};



template<size_t LenIndex>
struct BufferArg {
    static void print(pid_t pid, ptrace_syscall_info* info, size_t i) {
        unsigned long long addr = info->entry.args[i];
        size_t len = info->entry.args[LenIndex];

        if (!addr) {
            fprintf(LOG_FILE, "NULL");
            return;
        }

        if (len == 0) {
            fprintf(LOG_FILE, "\"\"");
            return;
        }

        std::vector<char> buffer(len);

        ssize_t n = read_child_memory(pid, buffer.data(), addr, len);

        if (n <= 0) {
            fprintf(LOG_FILE, "<invalid ptr>");
            return;
        }

        print_sanitized(buffer.data(), n);
    }

private:
    static void print_sanitized(const char* data, size_t len) {
        fprintf(LOG_FILE, "\"");

        for (size_t k = 0; k < len; k++) {
            unsigned char c = data[k];

            switch (c) {
                case '\n': fprintf(LOG_FILE, "\\n"); break;
                case '\t': fprintf(LOG_FILE, "\\t"); break;
                case '\r': fprintf(LOG_FILE, "\\r"); break;
                case '\\': fprintf(LOG_FILE, "\\\\"); break;
                case '"':  fprintf(LOG_FILE, "\\\""); break;

                default:
                    if (isprint(c))
                        fputc(c,LOG_FILE);
                    else
                        fprintf(LOG_FILE, "\\x%02x", c);
            }
        }

        fprintf(LOG_FILE, "\"");
    }
};