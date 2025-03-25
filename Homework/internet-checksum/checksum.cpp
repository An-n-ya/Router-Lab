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
        uint32_t n = ntohs(ip6->ip6_src.s6_addr16[i]);
        /*printf("src n %d: 0x%x -> 0x%x\n", i, ip6->ip6_src.s6_addr16[i], n);*/
        sum += n;
    }
    for (int i = 0; i < 8; i++) {
        uint32_t n = ntohs(ip6->ip6_dst.s6_addr16[i]);
        /*printf("dst n %d: 0x%x -> 0x%x\n", i, ip6->ip6_src.s6_addr16[i], n);*/
        sum += n;
    }
    uint32_t length = ntohs(ip6->ip6_plen);
    /*printf("len: 0x%x -> 0x%x\n", ip6->ip6_plen, length);*/
    sum += length;
    uint32_t nxt = ip6->ip6_nxt;
    /*printf("nxt: 0x%x -> 0x%x\n", ip6->ip6_nxt, nxt);*/
    sum += nxt;
}

void message_sum(uint16_t *data, size_t len, uint32_t &sum) {
    if (len == 0) {
        return;
    }
    int ind = 0;
    for (; ind * 2 < len - 1; ind += 1) {
        /*printf("data i:%d 0x%x -> 0x%x\n", ind, data[ind], ntohs(data[ind]));*/
        sum += ntohs(data[ind]);
    }
    if (len % 2 == 1) {
        uint16_t tmp = data[ind] & 0xff;
        /*printf("data i:%d 0x%x -> 0x%x\n", ind, tmp, ntohs(tmp));*/
        sum += ntohs(tmp);
    }
}

bool validate_checksum(uint32_t sum, uint16_t &checksum) {
    uint32_t sum_without_check = sum;
    sum += ntohs(checksum);
    while (sum_without_check > 0xffff) {
        sum_without_check = (sum_without_check & 0xffff) + ((sum_without_check & 0xffff0000) >> 16);
    }
    uint16_t check_sum = (uint16_t)sum_without_check;
    check_sum = ~check_sum;
    while (sum > 0xffff) {
        sum = (sum & 0xffff) + ((sum & 0xffff0000) >> 16);
    }
    /*printf("sum: 0x%x, check: 0x%x\n", sum, check_sum);*/
    checksum = htons(check_sum);
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

        return validate_checksum(sum, udp->check);
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

        return validate_checksum(sum, icmp->icmp6_cksum);
    } else {
        assert(false);
    }
    return true;
}
