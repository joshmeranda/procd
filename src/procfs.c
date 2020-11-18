#include <string.h>
#include <stdio.h>

#include "procfs.h"

int read_cmdline(pid_t pid, char cmdline[_POSIX_ARG_MAX]) {
  char cmdline_path[PATH_MAX];

  memset(cmdline_path, 0, PATH_MAX);

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

int read_user(pid_t pid, char user[LOGIN_NAME_MAX]) { /* todo: Not yet implemented */ return -1; }

int read_cwd(pid_t pid, char cwd[_POSIX_SYMLINK_MAX]) {
  char cwd_symlink[PATH_MAX];

  memset(cwd_symlink, 0, PATH_MAX);
  sprintf(cwd_symlink, "/proc/%d/cwd", pid);

  return readlink(cwd_symlink, cwd, _POSIX_SYMLINK_MAX);
}
