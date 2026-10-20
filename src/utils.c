#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include "utils.h"

void format_ipv4(uint32_t ip, char *buffer, size_t size)
{
    struct in_addr addr;
    addr.s_addr = ip;
    if (inet_ntop(AF_INET, &addr, buffer, (socklen_t)size) == NULL)
        snprintf(buffer, size, "unknown");
}

void format_timestamp(time_t value, char *buffer, size_t size)
{
    struct tm tm_value;
    if (localtime_r(&value, &tm_value) == NULL) {
        snprintf(buffer, size, "unknown-time");
        return;
    }
    strftime(buffer, size, "%Y-%m-%d %H:%M:%S", &tm_value);
}

int parse_uint(const char *text, unsigned int *value)
{
    char *end;
    unsigned long n;
    if (text == NULL || *text == '\0' || *text == '-') return -1;
    n = strtoul(text, &end, 10);
    if (*end != '\0' || n > 100000000UL) return -1;
    *value = (unsigned int)n;
    return 0;
}
