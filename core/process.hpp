#pragma once
#include <sys/types.h>
#include <stdio.h>
#include <string.h>

inline pid_t get_tgid(pid_t pid) {
    char path[64];
    char line[128];

    snprintf(path, sizeof(path), "/proc/%d/status", pid);

    FILE* f = fopen(path, "r");
    if (!f) return pid;

    pid_t tgid = pid;

    while (fgets(line, sizeof(line), f)) {
        if (strncmp(line, "Tgid:", 5) == 0) {
            sscanf(line, "Tgid:\t%d", &tgid);
            break;
        }
    }

    fclose(f);
    return tgid;
}