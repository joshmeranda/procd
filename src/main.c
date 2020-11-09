#include <malloc.h>
#include <stdio.h>

#include "procd.h"

int main() {
  conf_t conf;

  conf.pattern = malloc(sizeof(regex_t));

  if (parse_conf(&conf, "examples/simple.conf") != 0)
    return 1;

  int result = regexec(conf.pattern, "/usr/bin/ls", 0, NULL, REG_NOTBOL | REG_NOTEOL);

  printf("%d", result);

  return 0;
}