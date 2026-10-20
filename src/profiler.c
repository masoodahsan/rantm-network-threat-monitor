#include <string.h>
#include <stdio.h>
#include <arpa/inet.h>
#include "rantm.h"
#include "profiler.h"
#include "utils.h"

static SourceProfile profiles[RANTM_MAX_SOURCES];
static unsigned int profile_count = 0;

int profiler_find_or_add(uint32_t ip, const RantmConfig *config)
{
    unsigned int i;
    unsigned int limit = config->max_source_profiles;
    for (i = 0; i < profile_count; ++i)
        if (profiles[i].ip == ip) return (int)i;

    if (profile_count >= limit || profile_count >= RANTM_MAX_SOURCES) return -1;

    memset(&profiles[profile_count], 0, sizeof(profiles[profile_count]));
    profiles[profile_count].ip = ip;
    profiles[profile_count].window_start = time(NULL);
    profiles[profile_count].last_alert_score = -1;
    return (int)profile_count++;
}

SourceProfile *profiler_get(int index)
{
    if (index < 0 || (unsigned int)index >= profile_count) return NULL;
    return &profiles[index];
}

void profiler_reset_window(SourceProfile *p, time_t now)
{
    if (!p) return;
    p->packets = p->tcp_packets = p->udp_packets = p->icmp_packets = 0;
    p->syn_packets = p->synack_packets = 0;
    p->unique_ports = 0;
    memset(p->ports, 0, sizeof(p->ports));
    p->risk_score = 0;
    p->window_start = now;
}

void profiler_track_port(SourceProfile *p, uint16_t port)
{
    unsigned int i;
    if (!p) return;
    for (i = 0; i < p->unique_ports; ++i)
        if (p->ports[i] == port) return;
    if (p->unique_ports < RANTM_MAX_PORTS)
        p->ports[p->unique_ports++] = port;
}

void profiler_update_baseline(SourceProfile *p, double rate)
{
    const double alpha = 0.20;
    if (!p) return;
    if (p->completed_windows == 0)
        p->baseline_packets_per_second = rate;
    else
        p->baseline_packets_per_second =
            alpha * rate + (1.0 - alpha) * p->baseline_packets_per_second;
    p->completed_windows++;
}

void profiler_print_all(void)
{
    unsigned int i;
    for (i = 0; i < profile_count; ++i) {
        char ip[INET_ADDRSTRLEN];
        format_ipv4(profiles[i].ip, ip, sizeof(ip));
        printf("%-16s packets=%lu baseline=%.2f pkt/s\n", ip,
               profiles[i].packets, profiles[i].baseline_packets_per_second);
    }
}
