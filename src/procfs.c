#include <string.h>
#include <stdio.h>
#include <pwd.h>

#include "procfs.h"

/**
 * Macros for file sizes of specific procfs files, assumes max pid of 2^22 (4194304)
 * for 7 bytes and will include the null byte.
 */
#define PROCFS_MAX_CMDLINE 22       // "/proc/[pid]/cmdline"
#define PROCFS_MAX_LOGINUID 23      // "/proc/[pid]]/loginuid"
#define PROCFS_MAX_CWD 18           // "/proc/[pid]]/cwd"

int read_cmdline(pid_t pid, char cmdline[_POSIX_ARG_MAX]) {
  char cmdline_path[PROCFS_MAX_CMDLINE];

  sprintf(cmdline_path, "/proc/%d/cmdline", pid);

  FILE *stream = fopen(cmdline_path, "r");

  if (stream == NULL) {
    return -1;
  }

  int n = (int) fread(cmdline, 1, _POSIX_ARG_MAX, stream);
  fclose(stream);

  // replace null character delimiter with spaces
  for (int i = 0; i < n - 1; ++i) {
    if (cmdline[i] == 0) {
      cmdline[i] = ' ';
    }
  }

  return n;
}

// todo: not good
int read_login(pid_t pid, char user[LOGIN_NAME_MAX]) {
  char loginuid_path[PROCFS_MAX_LOGINUID];

  sprintf(loginuid_path, "/proc/%d/loginuid", pid);

  FILE *stream = fopen(loginuid_path, "r");

  if (stream == NULL) {
    return -1;
  }

  int uid;
  struct passwd *uid_passwd;

  fscanf(stream, "%d\n", &uid);

  uid_passwd = getpwuid(uid);
  strcpy(user, uid_passwd->pw_name);

  return 0;
}

int read_cwd(pid_t pid, char cwd[_POSIX_SYMLINK_MAX]) {
  char cwd_symlink[PROCFS_MAX_CWD];

  sprintf(cwd_symlink, "/proc/%d/cwd", pid);

  int n = readlink(cwd_symlink, cwd, _POSIX_SYMLINK_MAX);

  // null terminate the read path
  cwd[n] = 0;

  return n;
}
