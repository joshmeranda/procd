#include <string.h>
#include <stdio.h>
#include <pwd.h>
#include <malloc.h>

#include "procfs.h"

/**
 * Macros for file sizes of specific procfs files, assumes max pid of 2^22 (4194304)
* for 7 characters and will include the null byte.
 */
#define PROCFS_MAX_CMDLINE 20       // "/proc/[pid]/cmdline"
#define PROCFS_MAX_ENVIRON 20       // "/proc/[pid]/environ"
#define PROCFS_MAX_CWD     16       // "/proc/[pid]/cwd"

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

int read_login(pid_t pid, char login[LOGIN_NAME_MAX]) {
  char environ_path[PROCFS_MAX_ENVIRON];

  sprintf(environ_path, "/proc/%d/environ", pid);

  FILE *stream = fopen(environ_path, "r");

  if (stream == NULL)
    return -1;

  char key[5], // looking for "USER" envvar so only need 5 bytes
       val[LOGIN_NAME_MAX];

  // no standardized size for each variable other than the max for ALL environment
  // variables: ~32 kB
  char *environ = NULL;
  size_t len = 0;

  while(getdelim(&environ, &len, '\0', stream) != -1) {
    memset(key, 0, sizeof(key));
    memset(val, 0, sizeof(val));

    // only take the first 9 (LOGIN_NAME_MAX) characters for the value
    sscanf(environ, "%5[^=]=%9s", key, val);

    // free before potential break
    free(environ);
    environ = NULL;
    len = 0;

    if (strcmp("USER", key) == 0) {
      strcpy(login, val);
      break;
    }
  }

  fclose(stream);

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
