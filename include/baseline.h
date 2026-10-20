#ifndef BASELINE_H
#define BASELINE_H
#include "rantm.h"
void baseline_update(SourceProfile *profile, double packets_per_second);
double baseline_deviation_score(const SourceProfile *profile, double current_rate);
#endif
