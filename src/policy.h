#ifndef POLICY_H
#define POLICY_H

#include <seccomp.h>

#define POLICY_BASIC  0
#define POLICY_STRICT 1

int get_policy_mode(const char *filename);

int load_policy(scmp_filter_ctx ctx,
                const char *filename,
                int mode);

#endif
