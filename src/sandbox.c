#include <stdio.h>
#include <errno.h>
#include <seccomp.h>

#include "sandbox.h"
#include "policy.h"


int setup_sandbox(const char *policy_file)
{
    int mode;

    /*
     * Determine whether this is BASIC or STRICT.
     */
    mode = get_policy_mode(policy_file);

    if (mode < 0)
    {
        fprintf(stderr,
                "[SecCage] Invalid policy mode\n");

        return -1;
    }

    scmp_filter_ctx ctx;

    /*
     * BASIC:
     * Allow system calls by default.
     *
     * STRICT:
     * Block system calls by default.
     */
    if (mode == POLICY_STRICT)
    {
        printf("[SecCage] Mode: STRICT\n");

        ctx = seccomp_init(SCMP_ACT_ERRNO(EPERM));
    }
    else
    {
        printf("[SecCage] Mode: BASIC\n");

        ctx = seccomp_init(SCMP_ACT_ALLOW);
    }

    if (ctx == NULL)
    {
        fprintf(stderr,
                "[SecCage] Failed to initialize seccomp\n");

        return -1;
    }

    /*
     * Load the rules from the policy file.
     */
    if (load_policy(ctx, policy_file, mode) != 0)
    {
        fprintf(stderr,
                "[SecCage] Failed to load policy\n");

        seccomp_release(ctx);
        return -1;
    }

    /*
     * Activate the seccomp filter.
     */
    if (seccomp_load(ctx) < 0)
    {
        fprintf(stderr,
                "[SecCage] Failed to load seccomp filter\n");

        seccomp_release(ctx);
        return -1;
    }

    seccomp_release(ctx);

    printf("[SecCage] Syscall filter installed\n");

    return 0;
}
