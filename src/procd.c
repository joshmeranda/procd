#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <linux/cn_proc.h>
#include <linux/connector.h>
#include <linux/netlink.h>

#include <sys/socket.h>
#include <fcntl.h>
#include <bits/fcntl-linux.h>
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

// todo: needed?
//#define PROC_CN_MCAST_LISTEN (1)
//#define PROC_CN_MCAST_IGNORE (2)

void handle_msg (struct cn_msg *cn_hdr) {
  // todo: replace '1024' with limits from limits.h (`man limits.h`)
  char cmdline[1024], fname1[1024], ids[1024], fname2[1024], buf[1024];
  int r = 0, fd, i;
  FILE *f = NULL;
  struct proc_event *ev = (struct proc_event *)cn_hdr->data;

  snprintf(fname1, sizeof(fname1), "/proc/%d/status", ev->event_data.exec.process_pid);
  snprintf(fname2, sizeof(fname2), "/proc/%d/cmdline", ev->event_data.exec.process_pid);

  f = fopen(fname1, "r");
  fd = open(fname2, O_RDONLY);

  memset(&cmdline, 0, sizeof(cmdline));
  memset(&ids, 0, sizeof(ids));

  while (f && fgets(buf, sizeof(buf), f) != NULL) {
    if (strstr(buf, "Uid")) {
      strtok(buf, "\n");
      snprintf(ids, sizeof(ids), "%s", buf);
    }
  }
  if (f)
    fclose(f);

  if (fd > 0) {
    r = read(fd, cmdline, sizeof(cmdline));
    close(fd);

    for (i = 0; r > 0 && i < r; ++i) {
      if (cmdline[i] == 0)
        cmdline[i] = ' ';
    }
  }

  switch(ev->what){
    case PROC_EVENT_FORK:
      printf("FORK:parent(pid,tgid)=%d,%d\tchild(pid,tgid)=%d,%d\t[%s]\n",
             ev->event_data.fork.parent_pid,
             ev->event_data.fork.parent_tgid,
             ev->event_data.fork.child_pid,
             ev->event_data.fork.child_tgid, cmdline);
      break;
    case PROC_EVENT_EXEC:
      printf("EXEC:pid=%d,tgid=%d\t[%s]\t[%s]\n",
             ev->event_data.exec.process_pid,
             ev->event_data.exec.process_tgid, ids, cmdline);
      break;
    case PROC_EVENT_EXIT:
      printf("EXIT:pid=%d,%d\texit code=%d\n",
             ev->event_data.exit.process_pid,
             ev->event_data.exit.process_tgid,
             ev->event_data.exit.exit_code);
      break;
    case PROC_EVENT_UID:
      printf("UID:pid=%d,%d ruid=%d,euid=%d\n",
             ev->event_data.id.process_pid, ev->event_data.id.process_tgid,
             ev->event_data.id.r.ruid, ev->event_data.id.e.euid);
      break;
    default:
      break;
  }
}

// todo: partition big boi into smaller bois
// todo: remove the goto statement
int init_service() {
  int sk_nl;
  int err;

  struct sockaddr_nl my_nla, kern_nla, from_nla;
  socklen_t from_nla_len;

  char buff[BUFF_SIZE];
  int retval = -1;

  struct nlmsghdr *nl_hdr;
  struct cn_msg *cn_hdr;
  enum proc_cn_mcast_op *mcop_msg;

  size_t recv_len = 0;

  // kernel connector access requires root level permissions
  if (getuid() != 0) {
    printf("Only root can start/stop the fork connector\n");
    return 0;
  }

  setvbuf(stdout, NULL, _IONBF, 0);

  // establish the connector communicator
  sk_nl = socket(PF_NETLINK, SOCK_DGRAM, NETLINK_CONNECTOR);
  if (sk_nl == -1) {
    perror("socket sk_nl error");
    return retval;
  }
  my_nla.nl_family = AF_NETLINK;
  my_nla.nl_groups = CN_IDX_PROC;
  my_nla.nl_pid = getpid();

  kern_nla.nl_family = AF_NETLINK;
  kern_nla.nl_groups = CN_IDX_PROC;
  kern_nla.nl_pid = 1;

  err = bind(sk_nl, (struct sockaddr *)&my_nla, sizeof(my_nla));
  if (err == -1) {
    printf("binding sk_nl error");
    goto close_and_exit;
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
    goto close_and_exit;
  }

  printf("sent\n");
  if (*mcop_msg == PROC_CN_MCAST_IGNORE) {
    retval = 0;
    goto close_and_exit;
  }

  // read process events from kernel
  for(memset(buff, 0, sizeof(buff)), from_nla_len = sizeof(from_nla);
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
      handle_msg(cn_hdr);
      if (nlh->nlmsg_type == NLMSG_DONE)
        break;
      nlh = NLMSG_NEXT(nlh, recv_len);
    }
  }
close_and_exit:
  close(sk_nl);
  exit(retval);

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