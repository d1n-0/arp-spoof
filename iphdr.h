#pragma once

#include <arpa/inet.h>
#include "ip.h"

struct IpHdr final {
    uint8_t version_and_ihl;
    uint8_t dscp_and_ecn;
    uint16_t total_length;
    uint16_t identification;
    uint16_t flags_and_fragment_offset;
    uint8_t ttl;
    uint8_t protocol;
    uint16_t checksum;
    uint32_t sip_;
    uint32_t dip_;

    Ip sip() { return Ip(ntohl(sip_)); }
    Ip dip() { return Ip(ntohl(dip_)); }
};