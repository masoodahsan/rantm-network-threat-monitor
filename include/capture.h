#ifndef CAPTURE_H
#define CAPTURE_H

#include <pcap.h>
#include "rantm.h"

int capture_run(const RantmConfig *config, char *error, size_t error_size);

#endif
