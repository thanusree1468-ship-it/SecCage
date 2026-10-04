# SecCage

## Syscall Sandboxing Tool

SecCage is a lightweight Linux system-call sandboxing tool written in C.

It uses **Linux Seccomp (Secure Computing Mode)** to restrict the system calls that a target program is allowed to execute.

The project supports configurable security policies, syscall filtering, process isolation, execution logging, and verbose execution information.

---

## Features

- System-call based sandboxing using Seccomp
- Configurable security policies
- BASIC and STRICT sandbox modes
- Parent-child process execution model
- Allowed syscall policy display
- Blocked syscall detection
- Execution status reporting
- Logging of sandbox execution
- Verbose command-line mode
- Test programs for safe and restricted behavior

---

## Project Architecture

```text
                    +------------------+
                    |     SecCage      |
                    |  Sandbox Tool    |
                    +--------+---------+
                             |
             +---------------+---------------+
             |               |               |
             v               v               v
       Process Control    Policies        Logging
             |               |               |
             v               v               v
         fork()/wait()   .conf files    seccage.log
             |
             v
       Child Process
             |
             v
      Seccomp Filter
             |
             v
       Target Program
