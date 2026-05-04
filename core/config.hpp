#pragma once

#include <cstdio>

inline int LOG_LEVEL = 0;

inline FILE *LOG_FILE = stderr;

#define LOG(lvl, fmt, ...) \
    do                     \
    {                      \
        if (LOG_LEVEL >= lvl) \
        {                  \
            fprintf(LOG_FILE, fmt, ##__VA_ARGS__); \
            fflush(LOG_FILE); \
        }                  \
    } while (0)
