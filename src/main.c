#include <malloc.h>

#include "procd.h"

int main() {
  conf_t conf;
  conf.pattern = malloc(sizeof(regex_t));

  if (parse_conf(&conf, "examples/simple.conf") != 0) {
    return 1;
  }

  init_service();

  free(conf.pattern);

  return 0;
}