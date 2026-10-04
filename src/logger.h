#ifndef LOGGER_H
#define LOGGER_H

void log_message(const char *level, const char *message);

void log_policy(const char *policy_file);

void log_target(const char *target_program);

void log_exit_status(int status);

void log_signal(int signal_number);

#endif
