#ifndef RANTM_H
#define RANTM_H

#include <stdint.h>
#include <stddef.h>
#include <time.h>
#include <pcap.h>

#define RANTM_MAX_SOURCES 1024
#define RANTM_MAX_PORTS 256
#define RANTM_DEFAULT_WINDOW_SECONDS 10

typedef struct {
    uint32_t ip;                 /* Stored in network byte order */
    time_t window_start;
    unsigned long packets;
    unsigned long tcp_packets;
    unsigned long udp_packets;
    unsigned long icmp_packets;
    unsigned long syn_packets;
    unsigned long synack_packets;
    unsigned int unique_ports;
    uint16_t ports[RANTM_MAX_PORTS];
    double baseline_packets_per_second;
    unsigned long completed_windows;
    int risk_score;
    int last_alert_score;
} SourceProfile;

typedef struct {
    char interface_name[128];
    char log_path[512];
    unsigned int window_seconds;
    unsigned int syn_threshold;
    unsigned int port_diversity_threshold;
    unsigned int udp_burst_threshold;
    unsigned int icmp_burst_threshold;
    unsigned int alert_threshold;
    unsigned int max_source_profiles;
} RantmConfig;

typedef struct {
    int syn_activity;
    int port_diversity;
    int udp_burst;
    int icmp_burst;
    int syn_imbalance;
    int baseline_deviation;
    int score;
    char level[16];
} RiskResult;

void config_defaults(RantmConfig *config);
int config_load(const char *path, RantmConfig *config, char *error, size_t error_size);

int profiler_find_or_add(uint32_t ip, const RantmConfig *config);
SourceProfile *profiler_get(int index);
void profiler_reset_window(SourceProfile *profile, time_t now);
void profiler_track_port(SourceProfile *profile, uint16_t port);
void profiler_update_baseline(SourceProfile *profile, double packet_rate);

void detector_process_packet(const unsigned char *packet, size_t caplen,
                             int datalink, const RantmConfig *config);
void risk_calculate(SourceProfile *profile, const RantmConfig *config,
                    RiskResult *result);
void logger_open(const char *path);
void logger_close(void);
void logger_alert(const SourceProfile *profile, const RiskResult *result);
void logger_message(const char *message);
void statistics_print(void);
void statistics_packet_seen(void);
void statistics_alert_seen(void);
void print_usage(const char *program);
void handle_packet(unsigned char *user, const struct pcap_pkthdr *header,
                   const unsigned char *packet);

#endif

