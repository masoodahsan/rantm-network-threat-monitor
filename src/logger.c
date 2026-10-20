#include <stdio.h>
#include <time.h>
#include <arpa/inet.h>
#include "logger.h"
#include "utils.h"

static FILE *log_file = NULL;

void logger_open(const char *path)
{
    log_file = fopen(path, "a");
    if (log_file == NULL)
        fprintf(stderr, "Warning: cannot open alert log '%s'; console alerts remain enabled.\n", path);
}

void logger_close(void)
{
    if (log_file != NULL) {
        fclose(log_file);
        log_file = NULL;
    }
}

void logger_message(const char *message)
{
    if (log_file != NULL) {
        time_t now = time(NULL);
        char timestamp[32];
        format_timestamp(now, timestamp, sizeof(timestamp));
        fprintf(log_file, "[%s] MESSAGE %s\n", timestamp, message);
        fflush(log_file);
    }
}

void logger_alert(const SourceProfile *p, const RiskResult *r)
{
    char ip[INET_ADDRSTRLEN], timestamp[32];
    time_t now = time(NULL);
    if (log_file == NULL || p == NULL || r == NULL) return;

    format_ipv4(p->ip, ip, sizeof(ip));
    format_timestamp(now, timestamp, sizeof(timestamp));
    fprintf(log_file,
            "[%s] level=%s source=%s risk=%d packets=%lu tcp=%lu udp=%lu "
            "icmp=%lu syn=%lu synack=%lu unique_ports=%u "
            "reasons=syn:%d,ports:%d,udp:%d,icmp:%d,imbalance:%d,baseline:%d\n",
            timestamp, r->level, ip, r->score, p->packets, p->tcp_packets,
            p->udp_packets, p->icmp_packets, p->syn_packets, p->synack_packets,
            p->unique_ports, r->syn_activity, r->port_diversity, r->udp_burst,
            r->icmp_burst, r->syn_imbalance, r->baseline_deviation);
    fflush(log_file);
}
