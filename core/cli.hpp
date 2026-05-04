#pragma once

#include <vector>
#include <sys/types.h>

struct CLIOptions
{
    bool attach_mode = false;

    int log_level = 0;

    const char *log_file = nullptr;
    const char *rules_file = "rules.json";

    std::vector<pid_t> pids;

    char **program_argv = nullptr;
};

bool parse_cli(int argc, char *argv[], CLIOptions &opts);