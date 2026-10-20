#ifndef PARSER_H
#define PARSER_H

#include <stddef.h>
#include <stdint.h>
#include <pcap.h>

typedef struct {
    uint32_t source_ip;
    uint32_t destination_ip;
    uint8_t protocol;
    uint16_t source_port;
    uint16_t destination_port;
    int tcp_syn;
    int tcp_ack;
    size_t network_header_length;
    size_t transport_header_length;
} ParsedPacket;

int parser_parse_packet(const unsigned char *packet, size_t caplen,
                        int datalink, ParsedPacket *parsed);

#endif
