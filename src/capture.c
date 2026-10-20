#include <stdio.h>
#include <string.h>
#include <pcap.h>
#include "capture.h"
#include "capture_internal.h"

int capture_run(const RantmConfig *config, char *error, size_t error_size)
{
    pcap_t *handle;
    int link_type;
    int result;
    char errbuf[PCAP_ERRBUF_SIZE] = {0};

    handle = pcap_open_live(config->interface_name, 65535, 1, 500,
                            errbuf);
    if (handle == NULL) {
        snprintf(error, error_size, "%s", errbuf);
        return -1;
    }

    link_type = pcap_datalink(handle);
    if (link_type != DLT_EN10MB) {
        snprintf(error, error_size,
                 "unsupported link type %d; this build expects Ethernet frames",
                 link_type);
        pcap_close(handle);
        return -1;
    }

    result = pcap_loop(handle, -1, packet_handler, (unsigned char *)config);
    if (result == -1) {
        snprintf(error, error_size, "%s", pcap_geterr(handle));
        pcap_close(handle);
        return -1;
    }

    pcap_close(handle);
    return 0;
}
