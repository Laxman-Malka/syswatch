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
// for cpp type correctness
#define PTRACE(req, ...) ptrace(static_cast<__ptrace_request>(req), __VA_ARGS__)
/* EXITKILL only for spawned processes — never for attach */
#define PTRACE_OPTS_SPAWN \
    (PTRACE_O_TRACESYSGOOD | \
     PTRACE_O_TRACEFORK    | \
     PTRACE_O_TRACECLONE   | \
     PTRACE_O_TRACEVFORK   | \
     PTRACE_O_TRACEEXEC    | \
     PTRACE_O_TRACEEXIT    | \
     PTRACE_O_EXITKILL)

#define PTRACE_OPTS_ATTACH \
    (PTRACE_O_TRACESYSGOOD | \
     PTRACE_O_TRACEFORK    | \
     PTRACE_O_TRACECLONE   | \
     PTRACE_O_TRACEVFORK   | \
     PTRACE_O_TRACEEXEC    | \
     PTRACE_O_TRACEEXIT)
/* ── tracee table ── */
#define MAX_TRACEES 4096

static pid_t  g_tracees[MAX_TRACEES];
static int    g_tracee_count = 0;
static int    g_attached = 0; /* 1 = attach mode, 0 = spawn mode */

static void tracee_add(pid_t pid) {
    if (g_tracee_count < MAX_TRACEES)
        g_tracees[g_tracee_count++] = pid;
}

static void tracee_remove(pid_t pid) {
    for (int i = 0; i < g_tracee_count; i++) {
        if (g_tracees[i] == pid) {
            g_tracees[i] = g_tracees[--g_tracee_count];
            return;
        }
    }
}

/* ── detach all live tracees ── */
static void detach_all(void) {
    fprintf(stderr, "[tracer] detaching %d tracee(s)...\n", g_tracee_count);

    for (int i = 0; i < g_tracee_count; i++) {
        pid_t pid = g_tracees[i];

        if (PTRACE(PTRACE_INTERRUPT, pid, 0, 0) == 0) {
            int status;

            if (waitpid(pid, &status, __WALL | WNOHANG) == -1) {
                if (errno != ECHILD)
                    perror("waitpid(detach)");
            }
        }

        if (PTRACE(PTRACE_DETACH, pid, 0, 0) == -1) {
            fprintf(stderr,
                    "[tracer] PTRACE_DETACH(%d): %s\n",
                    pid, strerror(errno));
        } else {
            fprintf(stderr,
                    "[tracer] detached from pid %d\n",
                    pid);
        }
    }

    g_tracee_count = 0;
}

/* ── signal handler ── */
static volatile sig_atomic_t g_stop = 0;

static void on_signal(int sig) {
    (void)sig;
    g_stop = 1;
}

/* ── attach to a single pid ── */
static int attach_one(pid_t pid) {
    if (PTRACE(PTRACE_SEIZE, pid, 0, PTRACE_OPTS_ATTACH) == -1) {
        fprintf(stderr, "PTRACE_SEIZE(%d): %s\n", pid, strerror(errno));
        return -1;
    }
    if (PTRACE(PTRACE_INTERRUPT, pid, 0, 0) == -1) {
        fprintf(stderr, "PTRACE_INTERRUPT(%d): %s\n", pid, strerror(errno));
        return -1;
    }
    int status;
    waitpid(pid, &status, __WALL);
    tracee_add(pid);
    return 0;
}

/* ── attach to an array of pids ── */
static int attach_process(pid_t *pids, int count) {
    int ok = 0;
    for (int i = 0; i < count; i++) {
        if (attach_one(pids[i]) == 0) {
            fprintf(stderr, "[tracer] attached to pid %d\n", pids[i]);
            ok++;
        }
    }
    return (ok > 0) ? 0 : -1;
}

/* ── spawn traced process ── */
static pid_t spawn_process(char *argv[]) {
    pid_t child = fork();
    if (child == -1) {
        perror("fork");
        return -1;
    }
    if (child == 0) {
        if (PTRACE(PTRACE_TRACEME, 0, NULL, NULL) == -1) {
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
    if (PTRACE(PTRACE_SETOPTIONS, child, 0, PTRACE_OPTS_SPAWN) == -1) {
        perror("PTRACE_SETOPTIONS");
        return -1;
    }
    tracee_add(child);
    return child;
}

/* ── print syscall entry ── */
static void print_entry(pid_t pid, const struct ptrace_syscall_info *info) {
    fprintf(stderr, "[pid %d] syscall(%llu) args: %llu %llu %llu %llu %llu %llu\n",
           pid,
           (unsigned long long)info->entry.nr,
           (unsigned long long)info->entry.args[0],
           (unsigned long long)info->entry.args[1],
           (unsigned long long)info->entry.args[2],
           (unsigned long long)info->entry.args[3],
           (unsigned long long)info->entry.args[4],
           (unsigned long long)info->entry.args[5]);
}

/* ── print syscall exit ── */
static void print_exit(pid_t pid, const struct ptrace_syscall_info *info) {
    fprintf(stderr, "[pid %d] -> return: %lld (error=%d)\n",
           pid,
           (long long)info->exit.rval,
           info->exit.is_error);
}

/* ── handle fork/clone/exec events ── */
static int handle_event(pid_t pid, int status) {
    int event = status >> 16;
    if (event == 0)
        return 0;

    unsigned long newpid = 0;

    if (PTRACE(PTRACE_GETEVENTMSG, pid, 0, &newpid) == -1) {
        perror("PTRACE_GETEVENTMSG");
        return 1;
    }

    switch (event) {
        case PTRACE_EVENT_FORK:
            fprintf(stderr, "[pid %d] fork -> %lu\n", pid, newpid);
            break;
        case PTRACE_EVENT_VFORK:
            fprintf(stderr, "[pid %d] vfork -> %lu\n", pid, newpid);
            break;
        case PTRACE_EVENT_CLONE:
            fprintf(stderr, "[pid %d] clone -> %lu\n", pid, newpid);
            break;
        case PTRACE_EVENT_EXEC:
            fprintf(stderr, "[pid %d] exec (old tid %lu)\n", pid, newpid);
            return 1;
        case PTRACE_EVENT_EXIT:
            fprintf(stderr, "[pid %d] about to exit (status=%lu)\n", pid, newpid);
            return 1;
        default:
            return 0;
    }

    if (newpid > 0) {
        tracee_add((pid_t)newpid);

        if (PTRACE(PTRACE_SYSCALL, (pid_t)newpid, 0, 0) == -1) {
            fprintf(stderr,
                    "PTRACE_SYSCALL(new %lu): %s\n",
                    newpid, strerror(errno));
        }
    }

    return 1;
}

/* ── handle stop ── */
static int handle_stop(pid_t pid, int status) {
    if (!WIFSTOPPED(status))
        return 0;

    if (handle_event(pid, status))
        return 0;

    int sig = WSTOPSIG(status);

    if (sig == (SIGTRAP | 0x80)) {
        struct ptrace_syscall_info info;
        memset(&info, 0, sizeof(info));

        if (PTRACE(PTRACE_GET_SYSCALL_INFO, pid,
                   sizeof(info), &info) == -1) {
            perror("PTRACE_GET_SYSCALL_INFO");
            return -1;
        }

        if (info.op == PTRACE_SYSCALL_INFO_ENTRY)
            print_entry(pid, &info);
        else if (info.op == PTRACE_SYSCALL_INFO_EXIT)
            print_exit(pid, &info);

        return 0;
    }

    /* swallow ptrace SIGTRAP */
  /* swallow ONLY pure ptrace traps */
if (sig == SIGTRAP) {
    /* distinguish real vs internal */
    if ((status >> 16) != 0)
        return 0;  // ptrace event

    /* otherwise forward real SIGTRAP */
    return SIGTRAP;
}

    /* forward real signals */
    return sig;
}

/* ── kick off tracing on already-seized pids ── */
static void resume_all(pid_t *pids, int count) {
    for (int i = 0; i < count; i++) {
        if (PTRACE(PTRACE_SYSCALL, pids[i], 0, 0) == -1)
            fprintf(stderr, "PTRACE_SYSCALL(%d): %s\n", pids[i], strerror(errno));
    }
}

/* ── main loop ── */
static void trace_loop(pid_t *initial, int count) {
    int status;

    resume_all(initial, count);

    while (!g_stop) {
        pid_t pid = waitpid(-1, &status, __WALL);

        if (pid == -1) {
            if (errno == EINTR) {
                /* woken by signal — check g_stop */
                continue;
            }
            if (errno == ECHILD) {
                fprintf(stderr, "[tracer] no more processes\n");
                break;
            }
            perror("waitpid");
            break;
        }

        if (WIFEXITED(status)) {
            fprintf(stderr, "[pid %d] exited (%d)\n", pid, WEXITSTATUS(status));
            tracee_remove(pid);
            continue;
        }

        if (WIFSIGNALED(status)) {
            fprintf(stderr, "[pid %d] killed by signal %d (%s)\n",
                   pid, WTERMSIG(status), strsignal(WTERMSIG(status)));
            tracee_remove(pid);
            continue;
        }

        if (!WIFSTOPPED(status))
            continue;

        int sig = handle_stop(pid, status);
        if (sig == -1)
            break;

        if (PTRACE(PTRACE_SYSCALL, pid, 0, sig) == -1) {
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
int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr,
            "Usage:\n"
            "  %s <program> [args...]\n"
            "  %s -p <pid> [pid...]\n",
            argv[0], argv[0]);
        return 1;
    }

    signal(SIGINT,  on_signal);
    signal(SIGTERM, on_signal);

    if (strcmp(argv[1], "-p") == 0) {
        if (argc < 3) {
            fprintf(stderr, "Missing PID\n");
            return 1;
        }

        g_attached = 1;

        int count = argc - 2;
        pid_t *pids = static_cast<pid_t*>( malloc(count * sizeof(pid_t)));
        if (!pids) { perror("malloc"); return 1; }

        for (int i = 0; i < count; i++) {
            pids[i] = (pid_t)atoi(argv[2 + i]);
            if (pids[i] <= 0) {
                fprintf(stderr, "Invalid pid: %s\n", argv[2 + i]);
                free(pids);
                return 1;
            }
        }

        if (attach_process(pids, count) == -1) {
            free(pids);
            return 1;
        }

        trace_loop(pids, count);
        free(pids);

    } else {
        g_attached = 0;
        pid_t child = spawn_process(&argv[1]);
        if (child == -1)
            return 1;
        trace_loop(&child, 1);
    }

    return 0;
}
