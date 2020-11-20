#ifndef PROCD_PROCD_H
#define PROCD_PROCD_H

#include <regex.h>

/**
 * Path specification strategies.
 */
enum {
  ALLOW, // white listing
  DENY   // black listing
} typedef strategy_t;

/**
 * Specifies the policy for matched paths.
 * todo: redirect output over using syslog (would remove the need for DRY)
 *   https://stackoverflow.com/questions/37585758/how-to-redirect-output-of-systemd-service-to-a-file
 */
enum {
  KILL,     // kill matched processes and log
  WARN,     // only log matched processes
  DRY       // only print matched processes to stdout (good for testing)
} typedef policy_t;

struct {
  regex_t *path_regex;

  regex_t *ignore_login_regex;

  strategy_t strategy;

  policy_t policy;

} typedef conf_t;

/**
 * Initialize the new service.
 *
 * @param conf
 * @return 0 if successful, -1 if not.
 */
int init_service(const conf_t *conf);

/**
 * Parse a configuration file to govern how the service should behave.
 *
 * @param conf A pointer to the destination struct.
 * @param path The path of the configuration file to read.
 * @return 0 if successful, -1 if not.
 */
int parse_conf(conf_t *conf, char *path);

#endif // PROCD_PROCD_H
