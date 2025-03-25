#include "checksum.h"
#include <assert.h>
#include <cstdint>
#include <cstdio>
#include <netinet/in.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

void ip6_header_sum(uint8_t *packet, uint32_t &sum) {
    struct ip6_hdr *ip6 = (struct ip6_hdr *)packet;
    for (int i = 0; i < 8; i++) {
        sum += ntohs(ip6->ip6_src.s6_addr16[i]);
        sum += ntohs(ip6->ip6_dst.s6_addr16[i]);
    }
    sum += ntohs(ip6->ip6_plen);
    sum += ip6->ip6_nxt;
}

void message_sum(const uint16_t *data, size_t len, uint32_t &sum) {
    for (size_t ind = 0; ind * 2 + 1 < len; ind += 1) {
        sum += ntohs(data[ind]);
    }
    if (len % 2 == 1) { // 处理剩余的一个字节
        sum += ntohs(data[len / 2] & 0xff);
    }
}

bool validate_checksum(uint32_t sum, uint16_t &checksum, bool is_icmp) {
    uint32_t sum_without_check = sum;
    sum += ntohs(checksum);
    while (sum_without_check > 0xffff) {
        sum_without_check = (sum_without_check & 0xffff) + (sum_without_check >> 16);
    }
    uint16_t computed_checksum = (uint16_t)sum_without_check;
    computed_checksum = ~computed_checksum;
    while (sum > 0xffff) {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    if (is_icmp) {
        if (computed_checksum == 0xffff && checksum == 0) {
            checksum = 0;
            return true;
        }
    } else {
        if (computed_checksum == 0 && checksum == 0xffff) {
            checksum = 0xffff;
            return true;
        }
        if (checksum == 0) {
            if (computed_checksum == 0) {
                checksum = htons(0xffff);
            } else {
                checksum = htons(computed_checksum);
            }
            return false;
        }
    }
    checksum = htons(computed_checksum);
    if (sum != 0xffff) {
        return false;
    } else {
        return true;
    }
}

bool validateAndFillChecksum(uint8_t *packet, size_t len) {
    struct ip6_hdr *ip6 = (struct ip6_hdr *)packet;

    // check next header
    uint8_t nxt_header = ip6->ip6_nxt;
    if (nxt_header == IPPROTO_UDP) {
        // UDP
        struct udphdr *udp = (struct udphdr *)&packet[sizeof(struct ip6_hdr)];
        uint32_t sum = 0;
        ip6_header_sum(packet, sum);

        sum += ntohs(udp->source);
        sum += ntohs(udp->dest);
        sum += ntohs(udp->len);
        int data_len = ntohs(udp->len) - 8;
        /*printf("data_len: %d\n", data_len);*/
        uint16_t *data = (uint16_t *)&packet[sizeof(struct ip6_hdr) + sizeof(struct udphdr)];

        message_sum(data, data_len, sum);

        return validate_checksum(sum, udp->check, false);
    } else if (nxt_header == IPPROTO_ICMPV6) {
        // ICMPv6
        struct icmp6_hdr *icmp = (struct icmp6_hdr *)&packet[sizeof(struct ip6_hdr)];
        uint32_t sum = 0;
        uint32_t payload_len = ntohs(ip6->ip6_plen);
        ip6_header_sum(packet, sum);
        sum += (icmp->icmp6_type << 8) + (icmp->icmp6_code);
        uint32_t message_len = payload_len - 4;
        uint16_t *data = (uint16_t *)&packet[sizeof(struct ip6_hdr) + 4];
        message_sum(data, message_len, sum);

        return validate_checksum(sum, icmp->icmp6_cksum, true);
    } else {
        assert(false);
    }
    return true;
}
