#include <stdio.h>
#include <time.h>
#include "rantm.h"
#include "parser.h"
#include "profiler.h"
#include "risk_engine.h"
#include "logger.h"
#include "statistics.h"
#include "detector.h"
#include "utils.h"

void detector_finalize_window(SourceProfile *profile, const RantmConfig *config)
{
    RiskResult result;
    double rate;
    time_t now = time(NULL);
    char ip[INET_ADDRSTRLEN];
    char timestamp[32];

    if (!profile || !config) return;
    risk_calculate(profile, config, &result);
    profile->risk_score = result.score;
    rate = (double)profile->packets / (double)config->window_seconds;

    if (result.score >= config->alert_threshold &&
        result.score != profile->last_alert_score) {
        format_ipv4(profile->ip, ip, sizeof(ip));
        format_timestamp(now, timestamp, sizeof(timestamp));
        printf("\n[%s] %s risk=%d/100 source=%s\n",
               timestamp, result.level, result.score, ip);
        printf("  packets=%lu SYN=%lu SYN/ACK=%lu UDP=%lu ICMP=%lu unique_ports=%u\n",
               profile->packets, profile->syn_packets, profile->synack_packets,
               profile->udp_packets, profile->icmp_packets, profile->unique_ports);
        printf("  reasons:");
        if (result.syn_activity) printf(" high-SYN(%d)", result.syn_activity);
        if (result.port_diversity) printf(" port-diversity(%d)", result.port_diversity);
        if (result.udp_burst) printf(" UDP-burst(%d)", result.udp_burst);
        if (result.icmp_burst) printf(" ICMP-burst(%d)", result.icmp_burst);
        if (result.syn_imbalance) printf(" SYN-imbalance(%d)", result.syn_imbalance);
        if (result.baseline_deviation) printf(" baseline-deviation(%d)", result.baseline_deviation);
        printf("\n");
        logger_alert(profile, &result);
        statistics_alert_seen();
        profile->last_alert_score = result.score;
    }

    baseline_update(profile, rate);
    profiler_reset_window(profile, now);
}
