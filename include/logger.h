#ifndef LOGGER_H
#define LOGGER_H
#include "rantm.h"
void logger_open(const char *path);
void logger_close(void);
void logger_alert(const SourceProfile *profile, const RiskResult *result);
void logger_message(const char *message);
#endif
