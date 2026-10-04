#include <stdio.h>
#include <time.h>

#include "logger.h"

#define LOG_FILE "logs/seccage.log"


void log_message(const char *level, const char *message)
{
    FILE *file;
    time_t now;
    struct tm *time_info;

    file = fopen(LOG_FILE, "a");

    if (file == NULL)
    {
        return;
    }

    now = time(NULL);
    time_info = localtime(&now);

    fprintf(file,
            "[%04d-%02d-%02d %02d:%02d:%02d] [%s] %s\n",
            time_info->tm_year + 1900,
            time_info->tm_mon + 1,
            time_info->tm_mday,
            time_info->tm_hour,
            time_info->tm_min,
            time_info->tm_sec,
            level,
            message);

    fclose(file);
}


void log_policy(const char *policy_file)
{
    char message[256];

    snprintf(message,
             sizeof(message),
             "Policy: %s",
             policy_file);

    log_message("INFO", message);
}


void log_target(const char *target_program)
{
    char message[256];

    snprintf(message,
             sizeof(message),
             "Target: %s",
             target_program);

    log_message("INFO", message);
}


void log_exit_status(int status)
{
    char message[256];

    snprintf(message,
             sizeof(message),
             "Target exited with status: %d",
             status);

    log_message("INFO", message);
}


void log_signal(int signal_number)
{
    char message[256];

    snprintf(message,
             sizeof(message),
             "Target terminated by signal: %d",
             signal_number);

    log_message("WARN", message);
}
