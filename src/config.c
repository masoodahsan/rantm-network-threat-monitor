#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <stdlib.h>
#include "rantm.h"
#include "utils.h"

static char *trim(char *s)
{
    char *end;
    while (isspace((unsigned char)*s)) ++s;
    if (*s == '\0') return s;
    end = s + strlen(s) - 1;
    while (end > s && isspace((unsigned char)*end)) *end-- = '\0';
    return s;
}

void config_defaults(RantmConfig *c)
{
    memset(c, 0, sizeof(*c));
    c->window_seconds = 10;
    c->syn_threshold = 20;
    c->port_diversity_threshold = 15;
    c->udp_burst_threshold = 100;
    c->icmp_burst_threshold = 50;
    c->alert_threshold = 30;
    c->max_source_profiles = RANTM_MAX_SOURCES;
    snprintf(c->log_path, sizeof(c->log_path), "logs/alerts.log");
}

int config_load(const char *path, RantmConfig *c, char *error, size_t error_size)
{
    FILE *f = fopen(path, "r");
    char line[1024];
    unsigned int value;
    unsigned int line_number = 0;

    /* Missing config is acceptable; defaults and command-line options still work. */
    if (f == NULL) return 0;

    while (fgets(line, sizeof(line), f) != NULL) {
        char *key, *val, *equals;
        ++line_number;
        key = trim(line);
        if (*key == '\0' || *key == '#' || *key == ';') continue;
        equals = strchr(key, '=');
        if (equals == NULL) {
            snprintf(error, error_size, "line %u: expected key=value", line_number);
            fclose(f);
            return -1;
        }
        *equals = '\0';
        val = trim(equals + 1);
        key = trim(key);

        if (strcmp(key, "interface") == 0) {
            snprintf(c->interface_name, sizeof(c->interface_name), "%s", val);
        } else if (strcmp(key, "log_file") == 0) {
            snprintf(c->log_path, sizeof(c->log_path), "%s", val);
        } else {
            if (parse_uint(val, &value) != 0) {
                snprintf(error, error_size, "line %u: invalid integer for %s",
                         line_number, key);
                fclose(f);
                return -1;
            }
            if (strcmp(key, "window_seconds") == 0) c->window_seconds = value;
            else if (strcmp(key, "syn_threshold") == 0) c->syn_threshold = value;
            else if (strcmp(key, "port_diversity_threshold") == 0)
                c->port_diversity_threshold = value;
            else if (strcmp(key, "udp_burst_threshold") == 0)
                c->udp_burst_threshold = value;
            else if (strcmp(key, "icmp_burst_threshold") == 0)
                c->icmp_burst_threshold = value;
            else if (strcmp(key, "alert_threshold") == 0)
                c->alert_threshold = value;
            else if (strcmp(key, "max_source_profiles") == 0)
                c->max_source_profiles = value;
            else {
                snprintf(error, error_size, "line %u: unknown key '%s'",
                         line_number, key);
                fclose(f);
                return -1;
            }
        }
    }
    fclose(f);

    if (c->window_seconds == 0 || c->max_source_profiles == 0 ||
        c->max_source_profiles > RANTM_MAX_SOURCES ||
        c->alert_threshold > 100) {
        snprintf(error, error_size, "configuration value out of range");
        return -1;
    }
    return 0;
}
