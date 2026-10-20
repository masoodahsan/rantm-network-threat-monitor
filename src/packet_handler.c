#include <stdio.h>
#include <time.h>
#include <netinet/in.h>
#include <pcap.h>
#include "rantm.h"
#include "parser.h"
#include "profiler.h"
#include "detector.h"
#include "statistics.h"
#include "capture_internal.h"

void packet_handler(unsigned char *user, const struct pcap_pkthdr *header,
                    const unsigned char *packet)
{
    const RantmConfig *config = (const RantmConfig *)user;
    ParsedPacket parsed;
    int index;
    SourceProfile *profile;
    time_t now;

    if (!config || !header || !packet) return;
    if (!parser_parse_packet(packet, header->caplen,
                             DLT_EN10MB, &parsed)) {
        /* Non-IPv4 and malformed frames are intentionally ignored. */
        return;
    }

    index = profiler_find_or_add(parsed.source_ip, config);
    if (index < 0) return;
    profile = profiler_get(index);
    now = time(NULL);

    if (now - profile->window_start >= (time_t)config->window_seconds)
        detector_finalize_window(profile, config);

    profile->packets++;
    statistics_packet_seen();

    if (parsed.protocol == IPPROTO_TCP) {
        profile->tcp_packets++;
        if (parsed.tcp_syn && !parsed.tcp_ack) profile->syn_packets++;
        if (parsed.tcp_syn && parsed.tcp_ack) profile->synack_packets++;
        profiler_track_port(profile, parsed.destination_port);
    } else if (parsed.protocol == IPPROTO_UDP) {
        profile->udp_packets++;
        profiler_track_port(profile, parsed.destination_port);
    } else if (parsed.protocol == IPPROTO_ICMP) {
        profile->icmp_packets++;
    }
}
