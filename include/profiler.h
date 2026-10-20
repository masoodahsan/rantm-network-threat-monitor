#ifndef PROFILER_H
#define PROFILER_H
#include "rantm.h"
int profiler_find_or_add(uint32_t ip, const RantmConfig *config);
SourceProfile *profiler_get(int index);
void profiler_reset_window(SourceProfile *profile, time_t now);
void profiler_track_port(SourceProfile *profile, uint16_t port);
void profiler_update_baseline(SourceProfile *profile, double packet_rate);
void profiler_print_all(void);
#endif
