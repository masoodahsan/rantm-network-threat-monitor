#include <string.h>
#include <stdio.h>
#include "risk_engine.h"
#include "baseline.h"

void risk_calculate(SourceProfile *p, const RantmConfig *c, RiskResult *r)
{
    double duration, rate;
    int score = 0;
    memset(r, 0, sizeof(*r));

    if (p->syn_packets >= c->syn_threshold) {
        r->syn_activity = 25;
    } else if (p->syn_packets >= c->syn_threshold / 2U && c->syn_threshold > 1) {
        r->syn_activity = 10;
    }

    if (p->unique_ports >= c->port_diversity_threshold)
        r->port_diversity = 35;
    else if (p->unique_ports >= (c->port_diversity_threshold / 2U) &&
             c->port_diversity_threshold > 1)
        r->port_diversity = 15;

    if (p->udp_packets >= c->udp_burst_threshold)
        r->udp_burst = 20;
    else if (p->udp_packets >= c->udp_burst_threshold / 2U &&
             c->udp_burst_threshold > 1)
        r->udp_burst = 10;

    if (p->icmp_packets >= c->icmp_burst_threshold)
        r->icmp_burst = 20;
    else if (p->icmp_packets >= c->icmp_burst_threshold / 2U &&
             c->icmp_burst_threshold > 1)
        r->icmp_burst = 10;

    if (p->syn_packets >= c->syn_threshold / 2U &&
        p->syn_packets > 0 && p->synack_packets == 0)
        r->syn_imbalance = 10;

    duration = (double)c->window_seconds;
    rate = duration > 0 ? (double)p->packets / duration : 0.0;
    r->baseline_deviation = (int)baseline_deviation_score(p, rate);

    score = r->syn_activity + r->port_diversity + r->udp_burst +
            r->icmp_burst + r->syn_imbalance + r->baseline_deviation;
    if (score > 100) score = 100;
    r->score = score;

    if (score >= 80) snprintf(r->level, sizeof(r->level), "CRITICAL");
    else if (score >= 60) snprintf(r->level, sizeof(r->level), "HIGH");
    else if (score >= c->alert_threshold) snprintf(r->level, sizeof(r->level), "SUSPICIOUS");
    else snprintf(r->level, sizeof(r->level), "NORMAL");
}
