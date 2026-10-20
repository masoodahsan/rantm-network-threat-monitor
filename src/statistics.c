#include <stdio.h>
static unsigned long packet_count = 0;
static unsigned long alert_count = 0;

void statistics_packet_seen(void) { ++packet_count; }
void statistics_alert_seen(void) { ++alert_count; }

void statistics_print(void)
{
    printf("\nRANTM summary\n");
    printf("Packets processed: %lu\n", packet_count);
    printf("Alerts generated:  %lu\n", alert_count);
}
