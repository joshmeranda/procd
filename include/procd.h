#ifndef PROCD_PROCD_H
#define PROCD_PROCD_H

#include <regex.h>

/**
 * Path match strategy.
 */
enum {
  ALLOW, /* white listing */
  DENY   /* black listing */
} typedef strategy_t;

struct {
  regex_t **pattern;

  strategy_t match;

  int min_prune;
} typedef conf_t;

/**
 * Initialize the new service.
 *
 * @return 0 if successful, -1 if not.
 */
int init_service();

/**
 * Parse a configuration file to govern how the service should behave.
 *
 * @param conf A pointer to the destination struct.
 * @param path The path of the configuration file to read.
 * @return 0 if successful, -1 if not.
 */
int parse_conf(conf_t *conf, char *path);

#endif //PROCD_PROCD_H
