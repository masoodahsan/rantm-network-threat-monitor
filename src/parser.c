#include <string.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <pcap.h>
#include "parser.h"

/*
 * Bounds-check every header before reading it. This parser supports Ethernet
 * with optional VLAN tags and IPv4. Other link types and IPv6 are skipped.
 */
int parser_parse_packet(const unsigned char *packet, size_t caplen,
                        int datalink, ParsedPacket *out)
{
    size_t offset = 0;
    uint16_t ether_type;
    const unsigned char *ip;
    size_t ip_hlen, total_len, transport_offset;

    if (!packet || !out) return 0;
    memset(out, 0, sizeof(*out));

    if (datalink == DLT_EN10MB) {
        if (caplen < 14) return 0;
        ether_type = (uint16_t)((packet[12] << 8) | packet[13]);
        offset = 14;

        while (ether_type == 0x8100 || ether_type == 0x88a8 ||
               ether_type == 0x9100) {
            if (caplen < offset + 4) return 0;
            ether_type = (uint16_t)((packet[offset + 2] << 8) |
                                    packet[offset + 3]);
            offset += 4;
        }
        if (ether_type != 0x0800) return 0;
    } else if (datalink == DLT_RAW) {
        offset = 0;
    } else {
        return 0;
    }

    if (caplen < offset + 20) return 0;
    ip = packet + offset;
    if ((ip[0] >> 4) != 4) return 0;
    ip_hlen = (size_t)(ip[0] & 0x0f) * 4;
    if (ip_hlen < 20 || caplen < offset + ip_hlen) return 0;

    total_len = ((size_t)ip[2] << 8) | ip[3];
    if (total_len < ip_hlen) return 0;

    memcpy(&out->source_ip, ip + 12, 4);
    memcpy(&out->destination_ip, ip + 16, 4);
    out->protocol = ip[9];
    out->network_header_length = ip_hlen;
    transport_offset = offset + ip_hlen;

    /* Fragmented packets without the first fragment's transport header are skipped. */
    {
        uint16_t frag = (uint16_t)((ip[6] << 8) | ip[7]);
        if ((frag & 0x1fff) != 0) return 1;
    }

    if (out->protocol == IPPROTO_TCP) {
        if (caplen < transport_offset + 20) return 1;
        out->source_port = (uint16_t)((packet[transport_offset] << 8) |
                                      packet[transport_offset + 1]);
        out->destination_port = (uint16_t)((packet[transport_offset + 2] << 8) |
                                           packet[transport_offset + 3]);
        out->tcp_syn = (packet[transport_offset + 13] & 0x02) != 0;
        out->tcp_ack = (packet[transport_offset + 13] & 0x10) != 0;
        out->transport_header_length =
            (size_t)(packet[transport_offset + 12] >> 4) * 4;
        if (out->transport_header_length < 20) return 0;
        if (caplen < transport_offset + out->transport_header_length) return 1;
    } else if (out->protocol == IPPROTO_UDP) {
        if (caplen < transport_offset + 8) return 1;
        out->source_port = (uint16_t)((packet[transport_offset] << 8) |
                                      packet[transport_offset + 1]);
        out->destination_port = (uint16_t)((packet[transport_offset + 2] << 8) |
                                           packet[transport_offset + 3]);
        out->transport_header_length = 8;
    } else if (out->protocol == IPPROTO_ICMP) {
        out->transport_header_length = 8;
    }
    return 1;
}
