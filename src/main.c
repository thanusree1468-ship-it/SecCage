#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/wait.h>
#include <string.h>

#include "sandbox.h"
#include "logger.h"


void print_usage(const char *program)
{
    printf("\n");
    printf("SecCage - Syscall Sandboxing Tool\n");
    printf("\n");

    printf("Usage:\n");
    printf("  %s --policy <file> <program>\n", program);
    printf("  %s --verbose --policy <file> <program>\n", program);

    printf("\n");

    printf("Options:\n");
    printf("  --policy <file>    Specify the sandbox policy\n");
    printf("  --verbose          Display detailed information\n");

    printf("\n");

    printf("Example:\n");
    printf("  %s --policy policies/basic.conf ./tests/safe_program\n",
           program);

    printf("\n");

    printf("Verbose example:\n");
    printf("  %s --verbose --policy policies/basic.conf ./tests/safe_program\n",
           program);

    printf("\n");
}


int main(int argc, char *argv[])
{
    const char *policy_file;
    const char *target_program;

    int verbose = 0;


    /*
     * Parse command-line arguments
     */

    if (argc == 4 &&
        strcmp(argv[1], "--policy") == 0)
    {
        /*
         * Normal mode
         *
         * ./seccage --policy file program
         */

        policy_file = argv[2];
        target_program = argv[3];
    }
    else if (argc == 5 &&
             strcmp(argv[1], "--verbose") == 0 &&
             strcmp(argv[2], "--policy") == 0)
    {
        /*
         * Verbose mode
         *
         * ./seccage --verbose --policy file program
         */

        verbose = 1;

        policy_file = argv[3];
        target_program = argv[4];
    }
    else
    {
        print_usage(argv[0]);
        return 1;
    }


    /*
     * Display SecCage information
     */

    printf("========================================\n");
    printf("          SecCage Sandbox\n");
    printf("========================================\n");

    printf("[SecCage] Policy: %s\n", policy_file);
    printf("[SecCage] Target: %s\n", target_program);


    /*
     * Display verbose information
     */

    if (verbose)
    {
        printf("[SecCage] Verbose mode: ON\n");
        printf("[SecCage] Detailed execution information enabled\n");
    }


    /*
     * Start logging
     */

    log_message("INFO", "SecCage started");

    log_policy(policy_file);

    log_target(target_program);


    /*
     * Create child process
     */

    pid_t pid = fork();


    if (pid < 0)
    {
        perror("[SecCage] fork failed");

        log_message("ERROR", "fork failed");

        return 1;
    }


    /*
     * Child process
     */

    if (pid == 0)
    {
        printf("[SecCage] Child process created (PID: %d)\n",
               getpid());


        /*
         * Install sandbox before exec()
         */

        if (setup_sandbox(policy_file) != 0)
        {
            fprintf(stderr,
                    "[SecCage] Sandbox setup failed\n");

            log_message("ERROR",
                        "Sandbox setup failed");

            exit(1);
        }


        /*
         * Execute target program
         */

        printf("[SecCage] Executing target program...\n");

        log_message("INFO",
                    "Sandbox installed successfully");

        log_message("INFO",
                    "Executing target program");


        execl(target_program,
              target_program,
              (char *)NULL);


        /*
         * execl() returns only if execution fails
         */

        perror("[SecCage] exec failed");

        log_message("ERROR",
                    "Target program execution failed");

        exit(1);
    }


    /*
     * Parent process
     */

    else
    {
        int status;


        printf("[SecCage] Parent waiting for child (PID: %d)...\n",
               pid);


        /*
         * Wait for child process
         */

        waitpid(pid, &status, 0);


        /*
         * Target exited normally
         */

        if (WIFEXITED(status))
        {
            int exit_status = WEXITSTATUS(status);

            printf("[SecCage] Target exited with status: %d\n",
                   exit_status);

            if (verbose)
            {
                printf("[SecCage] Verbose: Normal process termination\n");
            }

            log_exit_status(exit_status);
        }


        /*
         * Target terminated by signal
         */

        else if (WIFSIGNALED(status))
        {
            int signal_number = WTERMSIG(status);

            printf("[SecCage] Target terminated by signal: %d\n",
                   signal_number);

            if (verbose)
            {
                printf("[SecCage] Verbose: Process terminated by signal\n");
            }

            log_signal(signal_number);
        }


        /*
         * Execution completed
         */

        printf("[SecCage] Execution finished.\n");

        log_message("INFO",
                    "Execution finished");
    }


    return 0;
}
