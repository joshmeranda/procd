#ifndef PROCD_PROCFS_H
#define PROCD_PROCFS_H

#include <limits.h>
#include <unistd.h>

/**
 * Read the command line arguments for the given pid.
 *
 * @param pid The target pid.
 * @param cmdline The address where the command line arguments will be stored.
 * @return The number of bytes read into cmdline, or -1 on error.
 */
int read_cmdline(pid_t pid, char cmdline[_POSIX_ARG_MAX]);

/**
 * Read the owner of the given pid.
 *
 * @param pid The target pid.
 * @param user THe address where the owner login name will be stored.
 * @return The number of bytes read into user, or -1 on error.
 */
int read_user(pid_t pid, char user[LOGIN_NAME_MAX]);

/**
 * Resolve the current working directory (cwd) of the given pid.
 *
 * @param pid The target pid.
 * @param cwd The address where the cwd will be stored.
 * @return The number of bytes read into cwd, or -1 on error.
 */
int read_cwd(pid_t pid, char cwd[_POSIX_SYMLINK_MAX]);

#endif // PROCD_PROCFS_H
