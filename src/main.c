#include <malloc.h>
#include <regex.h>

#include "procd.h"


// todo: implement basic command line interface
//   specify a config file path
int main() {
  conf_t conf;
  conf.pattern = malloc(sizeof(regex_t));

  if (parse_conf(&conf, "/etc/procd.conf") != 0) {
    return 1;
  }

  init_service(&conf);

  regfree(conf.pattern);

  return 0;
}