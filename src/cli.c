#include <stdio.h>
void print_usage(const char *program)
{
    printf("Usage: %s [-c config-file] [-i interface] [-l log-file]\n", program);
    printf("Options:\n");
    printf("  -c FILE   Configuration file (default: config/rantm.conf)\n");
    printf("  -i IFACE  Network interface to monitor (overrides config)\n");
    printf("  -l FILE   Alert log path (overrides config)\n");
    printf("  -h        Show this help\n");
}
