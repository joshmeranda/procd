#include <getopt.h>
#include <limits.h>
#include <malloc.h>
#include <regex.h>
#include <string.h>

#include "procd.h"

const char *USAGE = "Usage: procd [-hvf]\n";

int main(int argc, char **argv) {
  int opt;
  char config_path[PATH_MAX];

  memset(config_path, 0, sizeof(config_path));

  while ((opt = getopt(argc, argv, "hvf:")) != -1) {
    switch (opt) {
      case 'h':
        printf("%s", USAGE);
        return 0;
      case 'v':
        printf("v0.0.1-rc\n");
        return 0;
      case 'f':
        strcpy(config_path, optarg);
        break;
      default:
        fprintf(stderr, "%s", USAGE);
        return 1;
    }
  }

  // assign default config path if none passed
  if (config_path[0] == 0) {
    strcpy(config_path, "/etc/procd.conf");
  }

  conf_t conf;
  conf.pattern = malloc(sizeof(regex_t));

  if (parse_conf(&conf, config_path) != 0) {
    fprintf(stderr, "Error parsing config");
    return 1;
  }

  int retval = init_service(&conf);

  regfree(conf.pattern);

  return retval;
}