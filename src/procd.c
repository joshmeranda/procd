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

static void on_sigint(int _) { /* todo: not yet implemented */ }

#define SEND_MESSAGE_LEN (NLMSG_LENGTH(sizeof(struct cn_msg) + \
				       sizeof(enum proc_cn_mcast_op)))
#define RECV_MESSAGE_LEN (NLMSG_LENGTH(sizeof(struct cn_msg) + \
				       sizeof(struct proc_event)))

#define SEND_MESSAGE_SIZE    (NLMSG_SPACE(SEND_MESSAGE_LEN))
#define RECV_MESSAGE_SIZE    (NLMSG_SPACE(RECV_MESSAGE_LEN))

#define max(x,y) ((y)<(x)?(x):(y))
#define min(x,y) ((y)>(x)?(x):(y))

#define BUFF_SIZE (max(max(SEND_MESSAGE_SIZE, RECV_MESSAGE_SIZE), 1024))
#define MIN_RECV_SIZE (min(SEND_MESSAGE_SIZE, RECV_MESSAGE_SIZE))

static void handle_msg (struct cn_msg *cn_hdr, const conf_t *conf) {
  // todo: replace '1024' with limits from limits.h (`man limits.h`)
  char proc_cwd_symlink[1024], proc_cwd_real[1024], buf[1024];
  struct proc_event *ev = (struct proc_event *)cn_hdr->data;

  memset(proc_cwd_symlink, 0, sizeof(proc_cwd_symlink));
  memset(proc_cwd_real, 0, sizeof(proc_cwd_real));

  switch (ev->what) {
    case PROC_EVENT_FORK:
      snprintf(proc_cwd_symlink, sizeof(proc_cwd_symlink), "/proc/%d/cwd", ev->event_data.exec.process_pid);

      if (readlink(proc_cwd_symlink, proc_cwd_real, sizeof(proc_cwd_real)) == -1) {
        syslog(LOG_ERR, "Could not retrieve reference from symbolic link at '%s'", proc_cwd_symlink);
        fprintf(stderr, "Could not retrieve reference from symbolic link at '%s'", proc_cwd_symlink);
      }

      int path_match = regexec(conf->pattern, proc_cwd_real, 0, NULL, 0);

      if (conf->strategy == ALLOW && path_match != 0
          || conf->strategy == DENY && path_match == 0) {

        kill(ev->event_data.fork.child_pid, SIGKILL);
      }

      break;

    default:
      break;
  }
}

// todo: partition big boi into smaller bois
int init_service(const conf_t *conf) {
  int sk_nl;
  int err;

  struct sockaddr_nl my_nla, kern_nla, from_nla;
  socklen_t from_nla_len;

  char buff[BUFF_SIZE];
  int retval = 0;

  struct nlmsghdr *nl_hdr;
  struct cn_msg *cn_hdr;
  enum proc_cn_mcast_op *mcop_msg;

  size_t recv_len = 0;

  // kernel connector access requires root level permissions
  if (getuid() != 0) {
    printf("Only root can start/stop the fork connector\n");
    return 0;
  }

  // set stdout buffer strategy to unbuffered for uninterrupted writes
  setvbuf(stdout, NULL, _IONBF, 0);

  // establish the connector communicator
  sk_nl = socket(PF_NETLINK, SOCK_DGRAM, NETLINK_CONNECTOR);
  if (sk_nl == -1) {
    perror("socket sk_nl error");
    return retval;
  }

  // create netlink addresses
  my_nla.nl_family = AF_NETLINK;
  my_nla.nl_groups = CN_IDX_PROC;
  my_nla.nl_pid = getpid();

  kern_nla.nl_family = AF_NETLINK;
  kern_nla.nl_groups = CN_IDX_PROC;
  kern_nla.nl_pid = 1;

  // bin the socket to the connector
  err = bind(sk_nl, (struct sockaddr *)&my_nla, sizeof(my_nla));
  if (err == -1) {
    printf("binding sk_nl error");
    close(sk_nl);
    exit(3);
  }

  nl_hdr = (struct nlmsghdr *)buff;
  cn_hdr = (struct cn_msg *)NLMSG_DATA(nl_hdr);
  mcop_msg = (enum proc_cn_mcast_op*)&cn_hdr->data[0];

  printf("sending proc connector: PROC_CN_MCAST_LISTEN... ");
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
  if (send(sk_nl, nl_hdr, nl_hdr->nlmsg_len, 0) != nl_hdr->nlmsg_len) {
    perror("failed to send proc connector mcast ctl op!\n");
    retval = 1;
  }

  printf("sent\n");
  if (*mcop_msg == PROC_CN_MCAST_IGNORE) {
    retval = 2;
  }

  openlog("procd", 0, 0);

  // read process events from kernels
  for(memset(buff, 0, sizeof(buff)), from_nla_len = sizeof(from_nla)
      ; retval == 0  // if an error occurred before loop, it is not entered
      ; memset(buff, 0, sizeof(buff)), from_nla_len = sizeof(from_nla)) {
    struct nlmsghdr *nlh = (struct nlmsghdr*)buff;

    memcpy(&from_nla, &kern_nla, sizeof(from_nla));
    recv_len = recvfrom(sk_nl, buff, BUFF_SIZE, 0,
                        (struct sockaddr*)&from_nla, &from_nla_len);

    if (from_nla.nl_pid != 0)
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

  close(sk_nl);
  exit(retval);
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
 * todo: double spaces would result in matching an empty string path
 *
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
    memset(key, 0, sizeof(key));
    memset(val, 0, sizeof(val));

    sscanf(line, "%s = %[^\n]", key, val);

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

  fclose(stream);
  free(line);

  return retval;
}
