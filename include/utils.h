#ifndef UTILS_H
#define UTILS_H
#include <stddef.h>
#include <stdint.h>
#include <time.h>
void format_ipv4(uint32_t ip, char *buffer, size_t size);
void format_timestamp(time_t value, char *buffer, size_t size);
int parse_uint(const char *text, unsigned int *value);
#endif
