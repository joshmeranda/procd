#include <limits.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <regex.h>
#include <syslog.h>

#include <linux/cn_proc.h>
#include <linux/connector.h>
#include <linux/netlink.h>

#include <sys/socket.h>

#include <libnet.h>

#include "procd.h"
#include "procfs.h"

#define SEND_MESSAGE_LEN (NLMSG_LENGTH(sizeof(struct cn_msg) + \
				       sizeof(enum proc_cn_mcast_op)))
#define RECV_MESSAGE_LEN (NLMSG_LENGTH(sizeof(struct cn_msg) + \
				       sizeof(struct proc_event)))

#define SEND_MESSAGE_SIZE    (NLMSG_SPACE(SEND_MESSAGE_LEN))
#define RECV_MESSAGE_SIZE    (NLMSG_SPACE(RECV_MESSAGE_LEN))

#define max(x,y) ((y)<(x)?(x):(y))
#define BUFF_SIZE (max(max(SEND_MESSAGE_SIZE, RECV_MESSAGE_SIZE), 1024))


#define no_match_regex(regex) (regcomp(regex, "$^", REG_EXTENDED))

/**
 * Handles any interrupts received in the init_service loop.
 */
static int received = 0;
static void handler(int _) { received = 1; }

static void handle_msg (struct cn_msg *cn_hdr, const conf_t *conf) {
  // retrieve the pid of the process events
  pid_t pid;
  struct proc_event *proc_event = (struct proc_event *)cn_hdr->data;

  switch (proc_event->what) {
    case PROC_EVENT_FORK:
      pid = proc_event->event_data.fork.child_pid;
      break;
    case PROC_EVENT_EXEC:
      pid = proc_event->event_data.exec.process_pid;
      break;
    default:
      return; // do nothing for other process event types
  }

  char cmdline[_POSIX_ARG_MAX], proc_cwd_real[_POSIX_SYMLINK_MAX], login[LOGIN_NAME_MAX];

  // find the path to the process's cwd
  // if the cwd cannot be determined no further actions can be taken
  if (read_cwd(pid, proc_cwd_real) == -1) {
    return;
  }

  // find the command line arguments that spawned the process if possible
  if (read_cmdline(pid, cmdline) == -1) {
    syslog(LOG_DEBUG, "Could not determine the command for pid '%d'", pid);
  }

  if (read_login(pid, login) == -1) {
    syslog(LOG_ERR, "Could not determine the login for pid '%d'", pid);
  }

  // do nothing for ignored users;
  if (regexec(conf->path_regex, login, 0, NULL, 0) == 0) return;

  // kill the target process if it matches a deny or does not match an allow rule
  int path_match = regexec(conf->path_regex, proc_cwd_real, 0, NULL, 0);

  if (conf->strategy == ALLOW && path_match != 0
      || conf->strategy == DENY && path_match == 0) {

    // handle matched process according to given policy
    switch (conf->policy) {
      case KILL:
        kill(pid, SIGKILL);
      case WARN:
        syslog(LOG_WARNING, "Found process %d started from '%s' by '%s': '%s'", pid, proc_cwd_real, login, cmdline);
        break;
      case DRY:
        printf("Found process %d started from '%s' by '%s': '%s'", pid, proc_cwd_real, login, cmdline);
    }
  }
}

/**
 * Bind local port for communication with the connector kernel module.
 *
 * @return The file descriptor of the bound socket, or -1 on an error and the
 *      socket is closed before being returned.
 */
static int netlink_sock() {
  // establish the connector communicator
  int sock_nl = socket(PF_NETLINK, SOCK_DGRAM, NETLINK_CONNECTOR);

  if (sock_nl == -1) {
    syslog(LOG_CRIT, "Error creating local NETLINK socket");
    return -1;
  }

  struct sockaddr_nl addr_nl;

  // create netlink addresses
  addr_nl.nl_family = AF_NETLINK;
  addr_nl.nl_groups = CN_IDX_PROC;
  addr_nl.nl_pid = getpid();

  // bind the socket to the netlink address
  if (bind(sock_nl, (struct sockaddr *)&addr_nl, sizeof(addr_nl)) == -1) {
    syslog(LOG_CRIT, "Error binding to NETLINK socket");
    close(sock_nl);
    return -1;
  }

  return sock_nl;
}

int init_service(const conf_t *conf) {
  int nl_sock, retval = 0;
  size_t recv_len = 0;

  struct sockaddr_nl nl_kern_addr, nl_src_addr;
  struct cn_msg *cn_hdr;

  socklen_t from_nla_len;

  char buff[BUFF_SIZE];

  openlog("procd", 0, LOG_AUTHPRIV);

  // kernel connector access requires root level permissions
  if (getuid() != 0) {
    syslog(LOG_CRIT, "Only root can start/stop the fork connector\n");
    closelog();
    return 1;
  }

  // set stdout buffer strategy to unbuffered for uninterrupted writes
  setvbuf(stdout, NULL, _IONBF, 0);

  if ((nl_sock = netlink_sock()) == -1) {
    closelog();
    return 1;
  }

  // handle any abort signals which may occur in the loop
  signal(SIGINT, handler);
  signal(SIGILL, handler);
  signal(SIGABRT, handler);
  signal(SIGFPE, handler);
  signal(SIGSEGV, handler);
  signal(SIGTERM, handler);

  // set up address for the process connector in the kernel space
  nl_kern_addr.nl_family = AF_NETLINK;
  nl_kern_addr.nl_groups = CN_IDX_PROC;
  nl_kern_addr.nl_pid = 1;

  // read process events from kernels
  for(memset(buff, 0, sizeof(buff)), from_nla_len = sizeof(nl_src_addr)
      ; received == 0
      ; memset(buff, 0, sizeof(buff)), from_nla_len = sizeof(nl_src_addr)) {
    struct nlmsghdr *nlh = (struct nlmsghdr*)buff;

    memcpy(&nl_src_addr, &nl_kern_addr, sizeof(nl_src_addr));
    recv_len = recvfrom(nl_sock, buff, BUFF_SIZE, 0,
                        (struct sockaddr*)&nl_src_addr, &from_nla_len);

    if (nl_src_addr.nl_pid != 0)
      continue;

    if (recv_len < 1)
      continue;

    while (NLMSG_OK(nlh, recv_len)) {
      cn_hdr = NLMSG_DATA(nlh);

      if (nlh->nlmsg_type == NLMSG_NOOP)
        continue;

      if ((nlh->nlmsg_type == NLMSG_ERROR) ||
          (nlh->nlmsg_type == NLMSG_OVERRUN))
        break;

      handle_msg(cn_hdr, conf);

      if (nlh->nlmsg_type == NLMSG_DONE)
        break;

      nlh = NLMSG_NEXT(nlh, recv_len);
    }
  }

  closelog();
  close(nl_sock);

  return retval;
}

/**
 * Build a single regex pattern_line out of a space delimited string of separate
 * patterns.
 *
 * If the given pattern_line is empty (strlen(pattern_line) == 0) the compiled
 * regex will match nothing.
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
 * todo: double spaces would result in matching an empty string path
 * todo: handle paths with spaces
 *
 * @param regex The pointer to the struct to contain the compiled regex.
 * @param pattern_line The string with space separated regex patterns.
 * @return 0 if successful, -1 if not.
 */
static int merge_patterns(regex_t *regex, const char *pattern_line) {
  char *pattern = malloc(strlen(pattern_line) + 1);

  strcpy(pattern, pattern_line);

  for (char *c = pattern; *c != 0; c++) {
    if (*c == ' ')
      *c = '|';
  }

  int retval = regcomp(regex, pattern, REG_EXTENDED) == 0 ? 0 : -1;

  free(pattern);
  return retval;
}


/**
 * Parse the file t the given path for the service configuration values.
 *
 * todo: default config values
 *
 * @param conf The pointer to the struct where to store config values.
 * @param path The path to the file to parse, assumes the files already exists.
 * @return 0 on successful parsing, -1 otherwise.
 */
int parse_conf(conf_t *conf, char *path) {
  FILE *stream = fopen(path, "r");

  // todo: specify line number for configuration parse issues
  char *line = NULL;
  size_t len = 0;
  int retval = 0;

  // todo: make this config parsing far more dynamic
  //     leaving very minimal until real functionality is completed
  //     allow inline comments & multiline assignment & ...
  char key[100], val[100];

  // set defaults where necessary
  conf->strategy = ALLOW;
  conf->policy = KILL;

  while (getline(&line, &len, stream) != -1) {
    // skip comments and empty lines
    if (line[0] == '#' || line[0] == '\n') continue;

    memset(key, 0, sizeof(key));
    memset(val, 0, sizeof(val));

    sscanf(line, "%s = %[^\n]", key, val);

    if (strcmp("strategy", key) == 0) {
      // match key value against support strategies
      if (strcmp("allow", val) == 0)
        conf->strategy = ALLOW;
      else if (strcmp("deny", val) == 0)
        conf->strategy = DENY;
      else {
        fprintf(stderr, "Unknown strategy value '%s'\n", val);
        retval = -1;
      }

    } else if (strcmp("paths", key) == 0) {
      // merge and compile regex
      int e;

      if ((e = merge_patterns(conf->path_regex, val)) != 0) {
        fprintf(stderr, "Regex compilation for 'patterns' failed with error code '%d'\n", e);
        retval = -1;
      }

    } else if (strcmp("policy", key) == 0) {
      if (strcmp("kill", val) == 0) {
        conf->policy = KILL;
      } else if (strcmp("warn", val) == 0) {
        conf->policy = WARN;
      } else if (strcmp("DRY", val) == 0) {
        conf->policy = DRY;
      } else {
        fprintf(stderr, "Unknown policy value '%s'\n", val);\
        return -1;
      }

    } else if (strcmp("ignore_logins", key) == 0) {
      int e;

      if ((e = merge_patterns(conf->ignore_login_regex, val)) != 0) {
        fprintf(stderr, "Regex compilation for 'ignore_login_regex' failed with error code '%d'\n", e);
        retval = -1;
      }

    } else {
      fprintf(stderr, "Unknown key '%s\n'", key);
      retval = -1;
    }

    if (retval != 0) {
      break;
    }
  }

  free(line);

  // initialize still NULL regex
//  if (conf->path_regex == NULL) no_match_regex(conf->path_regex);
//  if (conf->ignore_login_regex == NULL) no_match_regex(conf->ignore_login_regex);

  fclose(stream);

  return retval;
}
