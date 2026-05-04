#include <cstdio>
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <linux/ptrace.h>

#include "core/dispatcher.hpp"
#include "core/process.hpp"
#include "core/config.hpp"

// register syscalls
#include "syscalls/open.hpp"
#include "syscalls/openat.hpp"
#include "syscalls/read.hpp"
#include "syscalls/write.hpp"
#include "syscalls/close.hpp"

#include "syscalls/socket.hpp"
#include "syscalls/connect.hpp"
#include "syscalls/accept.hpp"
#include "syscalls/accept4.hpp"
#include "syscalls/sendto.hpp"
#include "syscalls/recvfrom.hpp"   
#include "syscalls/sendmsg.hpp"
#include "syscalls/recvmsg.hpp"
#include "syscalls/socketpair.hpp"

#include "syscalls/dup.hpp"
#include "syscalls/dup2.hpp"
#include "syscalls/dup3.hpp"
#include "syscalls/pipe.hpp"
#include "syscalls/pipe2.hpp"
#include "syscalls/generated_syscalls.hpp"
#include "core/cli.hpp"
#include "core/rules.hpp"
// for cpp type correctness
#define PTRACE(req, ...) ptrace(static_cast<__ptrace_request>(req), __VA_ARGS__)
/* EXITKILL only for spawned processes — never for attach */
#define PTRACE_OPTS_SPAWN    \
    (PTRACE_O_TRACESYSGOOD | \
     PTRACE_O_TRACEFORK |    \
     PTRACE_O_TRACECLONE |   \
     PTRACE_O_TRACEVFORK |   \
     PTRACE_O_TRACEEXEC |    \
     PTRACE_O_TRACEEXIT |    \
     PTRACE_O_EXITKILL)

#define PTRACE_OPTS_ATTACH   \
    (PTRACE_O_TRACESYSGOOD | \
     PTRACE_O_TRACEFORK |    \
     PTRACE_O_TRACECLONE |   \
     PTRACE_O_TRACEVFORK |   \
     PTRACE_O_TRACEEXEC |    \
     PTRACE_O_TRACEEXIT)
/* ── tracee table ── */
#define MAX_TRACEES 4096

static pid_t g_tracees[MAX_TRACEES];
static int g_tracee_count = 0;
static int g_attached = 0; /* 1 = attach mode, 0 = spawn mode */

static void tracee_add(pid_t pid)
{
    if (g_tracee_count < MAX_TRACEES)
        g_tracees[g_tracee_count++] = pid;
}

static void tracee_remove(pid_t pid)
{
    for (int i = 0; i < g_tracee_count; i++)
    {
        if (g_tracees[i] == pid)
        {
            g_tracees[i] = g_tracees[--g_tracee_count];
            return;
        }
    }
}

/* ── detach all live tracees ── */
static void detach_all(void)
{
    LOG(1, "[tracer] detaching %d tracee(s)...\n", g_tracee_count);

    for (int i = 0; i < g_tracee_count; i++)
    {
        pid_t pid = g_tracees[i];

        if (PTRACE(PTRACE_INTERRUPT, pid, 0, 0) == 0)
        {
            int status;

            if (waitpid(pid, &status, __WALL | WNOHANG) == -1)
            {
                if (errno != ECHILD)
                    perror("waitpid(detach)");
            }
        }

        if (PTRACE(PTRACE_DETACH, pid, 0, 0) == -1)
        {
            fprintf(stderr,
                    "[tracer] PTRACE_DETACH(%d): %s\n",
                    pid, strerror(errno));
        }
        else
        {
            fprintf(stderr,
                    "[tracer] detached from pid %d\n",
                    pid);
        }
    }

    g_tracee_count = 0;
}

/* ── signal handler ── */
static volatile sig_atomic_t g_stop = 0;

static void on_signal(int sig)
{
    (void)sig;
    g_stop = 1;
}

/* ── attach to a single pid ── */
static int attach_one(pid_t pid)
{
    if (PTRACE(PTRACE_SEIZE, pid, 0, PTRACE_OPTS_ATTACH) == -1)
    {
        fprintf(stderr, "PTRACE_SEIZE(%d): %s\n", pid, strerror(errno));
        return -1;
    }
    if (PTRACE(PTRACE_INTERRUPT, pid, 0, 0) == -1)
    {
        fprintf(stderr, "PTRACE_INTERRUPT(%d): %s\n", pid, strerror(errno));
        return -1;
    }
    int status;
    waitpid(pid, &status, __WALL);
    tracee_add(pid);
    return 0;
}

/* ── attach to an array of pids ── */
static int attach_process(pid_t *pids, int count)
{
    int ok = 0;
    for (int i = 0; i < count; i++)
    {
        if (attach_one(pids[i]) == 0)
        {
            LOG(1, "[tracer] attached to pid %d\n", pids[i]);
            ok++;
        }
    }
    return (ok > 0) ? 0 : -1;
}

/* ── spawn traced process ── */
static pid_t spawn_process(char *argv[])
{
    pid_t child = fork();
    if (child == -1)
    {
        perror("fork");
        return -1;
    }
    if (child == 0)
    {
        if (PTRACE(PTRACE_TRACEME, 0, NULL, NULL) == -1)
        {
            perror("PTRACE_TRACEME");
            exit(1);
        }
        raise(SIGSTOP);
        execvp(argv[0], argv);
        perror("execvp");
        exit(1);
    }
    int status;
    waitpid(child, &status, __WALL);
    if (PTRACE(PTRACE_SETOPTIONS, child, 0, PTRACE_OPTS_SPAWN) == -1)
    {
        perror("PTRACE_SETOPTIONS");
        return -1;
    }
    tracee_add(child);
    return child;
}

/* ── handle fork/clone/exec events ── */
static int handle_event(pid_t pid, int status)
{
    int event = status >> 16;
    if (event == 0)
        return 0;

    unsigned long newpid = 0;

    if (PTRACE(PTRACE_GETEVENTMSG, pid, 0, &newpid) == -1)
    {
        perror("PTRACE_GETEVENTMSG");
        return 1;
    }

    switch (event)
    {
    case PTRACE_EVENT_FORK:
        LOG(1, "[pid %d] fork -> %lu\n", pid, newpid);
        break;

    case PTRACE_EVENT_VFORK:
        LOG(1, "[pid %d] vfork -> %lu\n", pid, newpid);
        break;

    case PTRACE_EVENT_CLONE:
        LOG(1, "[pid %d] clone -> %lu\n", pid, newpid);
        break;

    case PTRACE_EVENT_EXEC:
        LOG(1, "[pid %d] exec (old tid %lu)\n", pid, newpid);
        return 1;

    case PTRACE_EVENT_EXIT:
        LOG(1, "[pid %d] about to exit (status=%lu)\n", pid, newpid);
        return 1;

    default:
        return 0;
    }

    // 🔥 CRITICAL FIX: properly initialize new tracee
    if (newpid > 0)
    {
        pid_t np = (pid_t)newpid;

        tracee_add(np);

        int opts = g_attached ? PTRACE_OPTS_ATTACH : PTRACE_OPTS_SPAWN;

        // 🔥 ensure child inherits correct tracing behavior
        if (PTRACE(PTRACE_SETOPTIONS, np, 0, opts) == -1)
        {
            fprintf(stderr,
                    "PTRACE_SETOPTIONS(new %d): %s\n",
                    np, strerror(errno));
        }

        // 🔥 resume child in syscall-tracing mode
        if (PTRACE(PTRACE_SYSCALL, np, 0, 0) == -1)
        {
            fprintf(stderr,
                    "PTRACE_SYSCALL(new %d): %s\n",
                    np, strerror(errno));
        }
    }

    return 1;
}

/* ── handle stop ── */
static int handle_stop(pid_t pid, int status)
{
    if (!WIFSTOPPED(status))
        return 0;

    int sig = WSTOPSIG(status);

    // ✅ syscall-stop (TRACESYSGOOD)
    if (sig == (SIGTRAP | 0x80))
    {
        struct ptrace_syscall_info info;
        memset(&info, 0, sizeof(info));

        if (PTRACE(PTRACE_GET_SYSCALL_INFO, pid, sizeof(info), &info) == -1)
        {
            perror("PTRACE_GET_SYSCALL_INFO");
            return -1;
        }

        // 🔥 CRITICAL SPLIT
        if (info.op == PTRACE_SYSCALL_INFO_ENTRY)
        {
            dispatch_entry(pid, &info);
        }
        else if (info.op == PTRACE_SYSCALL_INFO_EXIT)
        {
            dispatch_exit(pid, &info);
        }

        return 0;
    }

    // plain SIGTRAP (ignore)
    if (sig == SIGTRAP)
        return 0;

    // pass other signals through
    return sig;
}

/* ── kick off tracing on already-seized pids ── */
static void resume_all(pid_t *pids, int count)
{
    for (int i = 0; i < count; i++)
    {
        if (PTRACE(PTRACE_SYSCALL, pids[i], 0, 0) == -1)
            fprintf(stderr, "PTRACE_SYSCALL(%d): %s\n", pids[i], strerror(errno));
    }
}

/* ── main loop ── */
static void trace_loop(pid_t *initial, int count)
{
    int status;

    resume_all(initial, count);

    while (!g_stop)
    {
        pid_t pid = waitpid(-1, &status, __WALL);

        if (pid == -1)
        {
            if (errno == EINTR)
            {
                /* woken by signal — check g_stop */
                continue;
            }
            if (errno == ECHILD)
            {
                LOG(1, "[tracer] no more processes\n");
                break;
            }
            perror("waitpid");
            break;
        }

        if (WIFEXITED(status))
        {
            LOG(1, "[pid %d] exited (%d)\n", pid, WEXITSTATUS(status));
            tracee_remove(pid);
            continue;
        }

        if (WIFSIGNALED(status))
        {
            LOG(1, "[pid %d] killed by signal %d (%s)\n",
                    pid, WTERMSIG(status), strsignal(WTERMSIG(status)));
            tracee_remove(pid);
            continue;
        }

        if (!WIFSTOPPED(status))
            continue;
        // 🔥 FIRST handle ptrace events (fork/clone/exec)
        if (handle_event(pid, status))
        {
            // still need to resume parent
            if (PTRACE(PTRACE_SYSCALL, pid, 0, 0) == -1)
            {
                if (errno == ESRCH)
                    continue;
                perror("PTRACE_SYSCALL");
                break;
            }
            continue;
        }
        int sig = handle_stop(pid, status);
        if (sig == -1)
            break;

        if (PTRACE(PTRACE_SYSCALL, pid, 0, sig) == -1)
        {
            if (errno == ESRCH)
                continue;
            perror("PTRACE_SYSCALL");
            break;
        }
    }

    /* clean detach if in attach mode and tracees still alive */
    if (g_attached && g_tracee_count > 0)
        detach_all();
}

/* ── main ── */
int main(int argc, char *argv[])
{
    CLIOptions opts;

    if (!parse_cli(argc, argv, opts))
        return 1;

    // 🔥 logging setup
    LOG_LEVEL = opts.log_level;

    if (opts.log_file)
    {
        LOG_FILE = fopen(opts.log_file, "a");

        if (!LOG_FILE)
        {
            perror("fopen(log)");
            return 1;
        }
    }

    // 🔥 load rules
    rules::load_rules(opts.rules_file);

    // 🔥 signals
    signal(SIGINT, on_signal);
    signal(SIGTERM, on_signal);

    // ─────────────────────────────────────────────
    // ATTACH MODE
    // ─────────────────────────────────────────────
    if (opts.attach_mode)
    {
        g_attached = 1;

        int count = (int)opts.pids.size();

        if (count <= 0)
        {
            fprintf(stderr, "No pid specified\n");

            if (LOG_FILE && LOG_FILE != stderr)
                fclose(LOG_FILE);

            return 1;
        }

        if (attach_process(opts.pids.data(), count) == -1)
        {
            if (LOG_FILE && LOG_FILE != stderr)
                fclose(LOG_FILE);

            return 1;
        }

        trace_loop(opts.pids.data(), count);
    }

    // ─────────────────────────────────────────────
    // SPAWN MODE
    // ─────────────────────────────────────────────
    else
    {
        g_attached = 0;

        pid_t child = spawn_process(opts.program_argv);

        if (child == -1)
        {
            if (LOG_FILE && LOG_FILE != stderr)
                fclose(LOG_FILE);

            return 1;
        }

        trace_loop(&child, 1);
    }

    // 🔥 cleanup
    if (LOG_FILE && LOG_FILE != stderr)
        fclose(LOG_FILE);

    return 0;
}