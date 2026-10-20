#ifndef CAPTURE_INTERNAL_H
#define CAPTURE_INTERNAL_H
#include <pcap.h>
#include "rantm.h"
extern RantmConfig g_config;
void packet_handler(unsigned char *user, const struct pcap_pkthdr *header,
                    const unsigned char *packet);
#endif
