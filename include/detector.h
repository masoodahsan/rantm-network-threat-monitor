#ifndef DETECTOR_H
#define DETECTOR_H
#include "rantm.h"
void detector_set_config(const RantmConfig *config);
void detector_finalize_window(SourceProfile *profile, const RantmConfig *config);
#endif
