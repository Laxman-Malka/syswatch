#include "cli.hpp"

#include <cstring>
#include <cstdio>
#include <cstdlib>

static void usage(const char *prog)
{
    fprintf(stderr,
            "Usage:\n"
            "  %s [options] <program> [args...]\n"
            "  %s [options] -p <pid> [pid...]\n\n"
            "Options:\n"
            "  -p <pid...>   Attach mode\n"
            "  -l <file>     Log file\n"
            "  -r <file>     Rules file\n"
            "  -v            Verbose\n"
            "  -vv           More verbose\n"
            "  -vvv          Full verbose\n",
            prog, prog);
}

bool parse_cli(int argc, char *argv[], CLIOptions &opts)
{
    int argi = 1;

    while (argi < argc)
    {
        if (strcmp(argv[argi], "-v") == 0)
        {
            opts.log_level = 1;
            argi++;
        }
        else if (strcmp(argv[argi], "-vv") == 0)
        {
            opts.log_level = 2;
            argi++;
        }
        else if (strcmp(argv[argi], "-vvv") == 0)
        {
            opts.log_level = 3;
            argi++;
        }
        else if (strcmp(argv[argi], "-l") == 0)
        {
            if (argi + 1 >= argc)
            {
                fprintf(stderr, "-l requires file\n");
                return false;
            }

            opts.log_file = argv[argi + 1];
            argi += 2;
        }
        else if (strcmp(argv[argi], "-r") == 0)
        {
            if (argi + 1 >= argc)
            {
                fprintf(stderr, "-r requires file\n");
                return false;
            }

            opts.rules_file = argv[argi + 1];
            argi += 2;
        }
        else
        {
            break;
        }
    }

    if (argi < argc && strcmp(argv[argi], "-p") == 0)
    {
        opts.attach_mode = true;
        argi++;

        if (argi >= argc)
        {
            fprintf(stderr, "-p requires pid(s)\n");
            return false;
        }

        while (argi < argc)
        {
            pid_t pid = (pid_t)atoi(argv[argi]);

            if (pid <= 0)
            {
                fprintf(stderr, "Invalid pid: %s\n", argv[argi]);
                return false;
            }

            opts.pids.push_back(pid);
            argi++;
        }
    }
    else
    {
        if (argi >= argc)
        {
            usage(argv[0]);
            return false;
        }

        opts.program_argv = &argv[argi];
    }

    return true;
}