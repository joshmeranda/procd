#include <limits.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <regex.h>

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

/**
 * Handle process events received from the connector.
 *
 * @param cn_hdr The event message received from the connector.
 * @param conf The configuration specifying how the handler should behave.
 */
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
    printf("Could not determine the command for pid '%d'\n", pid);
  }

  if (read_login(pid, login) == -1) {
    printf("Could not determine the login for pid '%d'\n", pid);
  }

  // do nothing for ignored users
  if (regexec(conf->ignore_login_regex, login, 0, NULL, 0) == 0) {
    return;
  }

  // kill the target process if it matches a deny or does not match an allow rule
  int path_match = regexec(conf->path_regex, proc_cwd_real, 0, NULL, 0);

  if ((conf->strategy == ALLOW && path_match != 0)
      || (conf->strategy == DENY && path_match == 0)) {

    // handle matched process according to given policy
    switch (conf->policy) {
      case KILL:
        kill(pid, SIGKILL);
        printf("Killed process %d started from '%s' by '%s': '%s'\n", pid, proc_cwd_real, login, cmdline);
        break;
      case WARN:
        printf("Found process %d started from '%s' by '%s': '%s'\n", pid, proc_cwd_real, login, cmdline);
        break;
    }
  }
}

/**
 * Initialize the service.
 *
 * @param conf The configuration for the service.
 * @return 0 on success, or non-zero on an error.
 */
int init_service(const conf_t *conf) {
  int nl_sock;

  struct sockaddr_nl my_nla, nla_kernel, nla_src;
  socklen_t from_nla_len;

  char buff[BUFF_SIZE];

  struct nlmsghdr *nl_hdr;
  struct cn_msg *cn_hdr;
  enum proc_cn_mcast_op *mcop_msg;

  size_t recv_len = 0;

  // kernel connector access requires root level permissions
  if (getuid() != 0) {
    printf("Only root can start/stop the connector\n");
    return 1;
  }

  // set stdout buffer strategy to unbuffered for uninterrupted writes
  setvbuf(stdout, NULL, _IONBF, 0);

  // establish the connector communicator
  if ((nl_sock = socket(PF_NETLINK, SOCK_DGRAM, NETLINK_CONNECTOR)) == -1) {
    perror("Error creating local NETLINK socket\n");
    return 2;
  }

  // create netlink addresses
  my_nla.nl_family = AF_NETLINK;
  my_nla.nl_groups = CN_IDX_PROC;
  my_nla.nl_pid = getpid();

  nla_kernel.nl_family = AF_NETLINK;
  nla_kernel.nl_groups = CN_IDX_PROC;
  nla_kernel.nl_pid = 1;

  // bind the socket to the connector
  if (bind(nl_sock, (struct sockaddr *)&my_nla, sizeof(my_nla)) == -1) {
    perror("Error binding to NETLINK socket\n");
    close(nl_sock);
    return 3;
  }

  nl_hdr = (struct nlmsghdr *)buff;
  cn_hdr = (struct cn_msg *)NLMSG_DATA(nl_hdr);
  mcop_msg = (enum proc_cn_mcast_op*)&cn_hdr->data[0];

  memset(buff, 0, sizeof(buff));
  *mcop_msg = PROC_CN_MCAST_LISTEN;

  // initialize netlink packet header
  nl_hdr->nlmsg_len = SEND_MESSAGE_LEN;
  nl_hdr->nlmsg_type = NLMSG_DONE;
  nl_hdr->nlmsg_flags = 0;
  nl_hdr->nlmsg_seq = 0;
  nl_hdr->nlmsg_pid = getpid();

  // initialize connector packet header
  cn_hdr->id.idx = CN_IDX_PROC;
  cn_hdr->id.val = CN_VAL_PROC;
  cn_hdr->seq = 0;
  cn_hdr->ack = 0;
  cn_hdr->len = sizeof(enum proc_cn_mcast_op);

  // send the subscription packet
  if (send(nl_sock, nl_hdr, nl_hdr->nlmsg_len, 0) != nl_hdr->nlmsg_len) {
    perror("failed to send proc connector mcast ctl op!\n");
    close(nl_sock);
    return 4;
  }

  if (*mcop_msg == PROC_CN_MCAST_IGNORE) {
    close(nl_sock);
    return 5;
  }

  signal(SIGKILL, handler);

  // read process events from kernels
  for(memset(buff, 0, sizeof(buff)), from_nla_len = sizeof(nla_src)
      ; received == 0
      ; memset(buff, 0, sizeof(buff)), from_nla_len = sizeof(nla_src)) {
    struct nlmsghdr *nlh = (struct nlmsghdr*)buff;

    memcpy(&nla_src, &nla_kernel, sizeof(nla_src));
    recv_len = recvfrom(nl_sock, buff, BUFF_SIZE, 0,
                        (struct sockaddr*)&nla_src, &from_nla_len);

    if (nla_src.nl_pid != 0)
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

  close(nl_sock);
  return 0;
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

  int retval = regcomp(regex, pattern, REG_EXTENDED | REG_NOSUB) == 0 ? 0 : -1;

  free(pattern);
  return retval;
}

/**
 * Parse the file t the given path for the service configuration values.
 *
 * @param conf The pointer to the struct where to store config values.
 * @param path The path to the file to parse, assumes the files already exists.
 * @return 0 on successful parsing, -1 otherwise.
 */
int parse_conf(conf_t *conf, char *path) {
  FILE *stream = fopen(path, "r");

  char *line = malloc(4096);
  size_t len = 4096;

  int retval = 0;

  // todo: make this config parsing far more dynamic
  //   leaving very minimal until real functionality is completed
  //   allow inline comments & multiline assignment & ...
  char key[100], val[100];

  // set defaults where necessary
  conf->strategy = ALLOW;
  conf->policy = KILL;

  // flags for specifying if each pattern line was found
  int set_path = 0, set_login = 0;

  int lineno = 1;

  while (getline(&line, &len, stream) != -1) {
    // skip comments and empty lines
    if (line[0] == '#' || line[0] == '\n') continue;

    sscanf(line, "%s = %[^\n]", key, val);

    if (strcmp("strategy", key) == 0) {
      // match key value against support strategies
      if (strcmp("allow", val) == 0)
        conf->strategy = ALLOW;
      else if (strcmp("deny", val) == 0)
        conf->strategy = DENY;
      else {
        fprintf(stderr, "line %d: Unknown strategy value '%s'\n", lineno, val);
        retval = -1;
      }

    } else if (strcmp("paths", key) == 0) {
      // merge and compile regex
      int e;

      if ((e = merge_patterns(conf->path_regex, val)) != 0) {
        fprintf(stderr, "line %d: Regex compilation failed\n", lineno);
        retval = -1;
      }
      set_path = 1;

    } else if (strcmp("policy", key) == 0) {
      if (strcmp("kill", val) == 0) {
        conf->policy = KILL;
      } else if (strcmp("warn", val) == 0) {
        conf->policy = WARN;
      } else {
        fprintf(stderr, "line %d: Unknown policy value '%s'\n", lineno, val);\
      return -1;
      }

    } else if (strcmp("ignore_logins", key) == 0) {
      int e;

      if ((e = merge_patterns(conf->ignore_login_regex, val)) != 0) {
        fprintf(stderr, "line %d: Regex compilation failed\n", lineno);
        retval = -1;
      }
      set_login = 1;

    } else {
      fprintf(stderr, "line %d: Unknown key '%s\n'", lineno, key);
      retval = -1;
    }

    if (retval != 0) {
      break;
    }

    lineno++;
  }
  free(line);

  // initialize still NULL regex
  if (!set_path) no_match_regex(conf->path_regex);
  if (!set_login) no_match_regex(conf->ignore_login_regex);

  fclose(stream);

  return retval;
}
