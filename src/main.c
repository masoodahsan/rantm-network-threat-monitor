#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pcap.h>
#include "rantm.h"
#include "capture.h"
#include "logger.h"
#include "statistics.h"

RantmConfig g_config;
int main(int argc, char **argv)
{
    char error[PCAP_ERRBUF_SIZE] = {0};
    const char *config_path = "config/rantm.conf";
    int i;

    config_defaults(&g_config);

    for (i = 1; i < argc; ++i) {
        if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            print_usage(argv[0]);
            return 0;
        } else if (strcmp(argv[i], "-c") == 0 && i + 1 < argc) {
            config_path = argv[++i];
        } else if (strcmp(argv[i], "-i") == 0 && i + 1 < argc) {
            snprintf(g_config.interface_name, sizeof(g_config.interface_name),
                     "%s", argv[++i]);
        } else if (strcmp(argv[i], "-l") == 0 && i + 1 < argc) {
            snprintf(g_config.log_path, sizeof(g_config.log_path),
                     "%s", argv[++i]);
        } else {
            fprintf(stderr, "Unknown or incomplete argument: %s\n", argv[i]);
            print_usage(argv[0]);
            return 2;
        }
    }

    if (config_load(config_path, &g_config, error, sizeof(error)) != 0) {
        fprintf(stderr, "Configuration error: %s\n", error);
        return 2;
    }

    /* Command-line options take precedence over the configuration file. */
    for (i = 1; i < argc; ++i) {
        if (strcmp(argv[i], "-i") == 0 && i + 1 < argc) {
            snprintf(g_config.interface_name, sizeof(g_config.interface_name),
                     "%s", argv[++i]);
        } else if (strcmp(argv[i], "-l") == 0 && i + 1 < argc) {
            snprintf(g_config.log_path, sizeof(g_config.log_path),
                     "%s", argv[++i]);
        } else if (strcmp(argv[i], "-c") == 0 && i + 1 < argc) {
            ++i;
        }
    }

    if (g_config.interface_name[0] == '\0') {
        char errbuf[PCAP_ERRBUF_SIZE] = {0};
        pcap_if_t *devices = NULL;
        if (pcap_findalldevs(&devices, errbuf) == 0 && devices != NULL) {
            snprintf(g_config.interface_name, sizeof(g_config.interface_name),
                     "%s", devices->name);
            pcap_freealldevs(devices);
        } else {
            fprintf(stderr, "No interface selected. Use -i <interface>.\n");
            print_usage(argv[0]);
            return 2;
        }
    }

    logger_open(g_config.log_path);

    printf("RANTM — Real-Time Adaptive Network Threat Monitor\n");
    printf("Interface: %s | Window: %u seconds | Log: %s\n",
           g_config.interface_name, g_config.window_seconds, g_config.log_path);
    printf("Monitoring authorized traffic only. Press Ctrl+C to stop.\n");

    /*
     * capture_run owns the capture loop. The callback checks the signal flag
     * indirectly through the capture timeout; Ctrl+C exits the loop cleanly.
     */
    if (capture_run(&g_config, error, sizeof(error)) != 0) {
        fprintf(stderr, "Capture error: %s\n", error);
        logger_message(error);
        logger_close();
        return 1;
    }

    statistics_print();
    logger_close();
    return 0;
}
