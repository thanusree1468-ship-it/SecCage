#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <seccomp.h>

#include "policy.h"


int get_policy_mode(const char *filename)
{
    FILE *file;
    char line[256];

    file = fopen(filename, "r");

    if (file == NULL)
    {
        perror("[SecCage] Failed to open policy file");
        return -1;
    }

    while (fgets(line, sizeof(line), file) != NULL)
    {
        char mode[32];

        if (sscanf(line, "MODE %31s", mode) == 1)
        {
            fclose(file);

            if (strcmp(mode, "STRICT") == 0)
            {
                return POLICY_STRICT;
            }

            if (strcmp(mode, "BASIC") == 0)
            {
                return POLICY_BASIC;
            }
        }
    }

    fclose(file);

    fprintf(stderr,
            "[SecCage] Policy mode not specified\n");

    return -1;
}


int load_policy(scmp_filter_ctx ctx,
                const char *filename,
                int mode)
{
    FILE *file;
    char line[256];

    file = fopen(filename, "r");

    if (file == NULL)
    {
        perror("[SecCage] Failed to open policy file");
        return -1;
    }

    while (fgets(line, sizeof(line), file) != NULL)
    {
        char action[32];
        char syscall_name[64];

        /* Ignore comments and blank lines */
        if (line[0] == '#' || line[0] == '\n')
        {
            continue;
        }

        /* Ignore MODE line */
        if (strncmp(line, "MODE", 4) == 0)
        {
            continue;
        }

        if (sscanf(line, "%31s %63s",
                   action,
                   syscall_name) != 2)
        {
            continue;
        }

        int syscall_number =
            seccomp_syscall_resolve_name(syscall_name);

        if (syscall_number == __NR_SCMP_ERROR)
        {
            fprintf(stderr,
                    "[SecCage] Unknown syscall: %s\n",
                    syscall_name);

            fclose(file);
            return -1;
        }

        /*
         * BASIC POLICY
         */
        if (mode == POLICY_BASIC &&
            strcmp(action, "BLOCK") == 0)
        {
            if (seccomp_rule_add(ctx,
                                 SCMP_ACT_ERRNO(EPERM),
                                 syscall_number,
                                 0) < 0)
            {
                fprintf(stderr,
                        "[SecCage] Failed to block: %s\n",
                        syscall_name);

                fclose(file);
                return -1;
            }

            printf("[SecCage] Policy: BLOCK %s\n",
                   syscall_name);
        }

        /*
         * STRICT POLICY
         */
        else if (mode == POLICY_STRICT &&
                 strcmp(action, "ALLOW") == 0)
        {
            if (seccomp_rule_add(ctx,
                                 SCMP_ACT_ALLOW,
                                 syscall_number,
                                 0) < 0)
            {
                fprintf(stderr,
                        "[SecCage] Failed to allow: %s\n",
                        syscall_name);

                fclose(file);
                return -1;
            }

            printf("[SecCage] Policy: ALLOW %s\n",
                   syscall_name);
        }
    }

    fclose(file);

    return 0;
}
