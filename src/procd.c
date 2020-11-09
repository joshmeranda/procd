#include <malloc.h>
#include <stdio.h>
#include <signal.h>
#include <string.h>
#include <unistd.h>

#include <linux/cn_proc.h>
#include <linux/connector.h>
#include <linux/netlink.h>

#include <sys/socket.h>

#include "procd.h"

static void on_sigint(int _) { /* todo: not yet implemented */ }

/**
 * Connect to interprocess kernel interfaces.
 *
 * @return The file descriptor for the socket, or -1 on failure.
 */
static int nl_connect() {
  int nl_sock;
  struct sockaddr_nl sa_nl;

  nl_sock = socket(PF_NETLINK, SOCK_DGRAM, NETLINK_CONNECTOR);
  if (nl_sock == -1) {
    fprintf(stderr, "Could not connect to the socket");
    return -1;
  }

  sa_nl.nl_family = AF_NETLINK;
  sa_nl.nl_groups = CN_IDX_PROC;
  sa_nl.nl_pid = getpid();

  if (bind(nl_sock, (struct sockaddr *) &sa_nl, sizeof(sa_nl))) {
    fprintf(stderr, "COuld not bind to a socket");
    close(nl_sock);
    return -1;
  }

  return nl_sock;
}

static int set_proc_ev_listen(int nl_sock, int enable);

static int handle_proc_ev(int nl_sock);

static int set_proc_ev_listen(int nl_sock, int enable);

int init_service() {
  int nl_sock;
  int retval = 0;

  signal(SIGINT, &on_sigint);
  sigaction(SIGINT, SA_RESTART, NULL);

  nl_sock = nl_connect();
  if (nl_sock == -1)
    return 1;

  if (set_proc_ev_listen(nl_sock, 0) == -1) {
    retval = 1;
  }

  if (handle_proc_ev(nl_sock)) {
    retval = 1;
  }

  set_proc_ev_listen(nl_sock, 0);
  return 0;
}

/**
 * Build a single regex pattern_line out of a space delimited string of separate
 * patterns.
 *
 * Currently the patterns are merged by simply replacing all spaces with a pipe.
 * This presents the clear flaw that paths cannot contain spaces, and if they do
 * the patterns will not match correctly. That being said, if you are using
 * spaces in your file and directory names, I kindly ask that you reconsider
 * your life choices (snake and kebab case are fun!).
 *
 *   (ex)
 *     merge_patterns("/usr/bin/.* /usr/local/.*") -> /usr/bin/.*|/usr/local/.*
 *     merge_patterns("/path with spaces") -> /path|with|spaces
 *
 * @param pattern_line The string with space separated regex patterns.
 * @return 0 if successful, -1 if not.
 */
static int merge_patterns(regex_t *regex, char *pattern_line) {
  for (char *c = pattern_line; *c != 0; c++) {
    if (*c == ' ')
      *c = '|';
  }

  return regcomp(regex, pattern_line, REG_EXTENDED) == 0 ? 0 : -1;
}

int parse_conf(conf_t *conf, char *path) {
  FILE *stream = fopen(path, "r");

  // todo: give reason why the config could not be read
  if (stream == NULL) {
    fprintf(stderr, "Could not open file located at '%s'\n", path);
    return -1;
  }

  char *line = NULL;
  size_t len = 0;
  int retval = 0;

  // todo: remember to free the line
  // todo: make this config parsing far more dynamic
  //     leaving very minimal until real functionality is completed
  //     allow inline comments & multiline assignment & ...
  while (getline(&line, &len, stream) != -1) {
    // skip empty lines and comments
    if (line[0] == '#' || line[0] == '\n') continue;

    // todo: look for better methods
    char key[100], val[100];
    memset(key, 0, 100);
    memset(val, 0, 100);

    sscanf(line, "%s = %s\n", key, val);

    // todo: free space from above before exit
    if (strcmp("strategy", key) == 0) {
      // match key value against support strategies
      if (strcmp("allow", val) == 0)
        conf->strategy = ALLOW;
      else if (strcmp("deny", val) == 0)
        conf->strategy = DENY;
      else {
        fprintf(stderr, "Unknown strategy value '%s'", val);
        retval = -1;
      }

    } else if (strcmp("patterns", key) == 0) {
      // merge and compile regex
      int e;
      if ((e = merge_patterns(conf->pattern, val)) != 0) {
        fprintf(stderr, "Regex compilation failed with error code %d", e);
        retval = -1;
      }

    } else {
      fprintf(stderr, "Unknown key '%s'", key);
      retval = -1;
    }

    if (retval != 0) {
      break;
    }
  }

  free(line);

  return retval;
}