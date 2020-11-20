#include <getopt.h>
#include <limits.h>
#include <malloc.h>
#include <regex.h>
#include <string.h>
#include <unistd.h>

#include "procd.h"

const char *USAGE = "Usage: procd [-hvdf:]\n";

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
        if (access(config_path, R_OK) != 0) {
          printf("Could not access config file at '%s'\n", optarg);
          return 1;
        }

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
  conf.path_regex = malloc(sizeof(regex_t));
  conf.ignore_login_regex = malloc(sizeof(regex_t));

  if (parse_conf(&conf, config_path) != 0) {
    fprintf(stderr, "Error parsing config");
    return 1;
  }

  int retval = init_service(&conf);

  regfree(conf.path_regex);
  free(conf.path_regex);

  regfree(conf.ignore_login_regex);
  free(conf.ignore_login_regex);

  return retval;
}