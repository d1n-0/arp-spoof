#pragma once

#include <cstdio>
#include <pcap.h>
#include "ethhdr.h"
#include "arphdr.h"
#include "iphdr.h"
#include "util.h"

struct SendArpReplyArgs {
    volatile bool *running;
    char *dev;
    Mac *attacker_mac;
    Ip *attacker_ip;
    Mac *sender_mac;
    Ip *sender_ip;
    Mac *target_mac;
    Ip *target_ip;
};

struct RelayPacketArgs {
    volatile bool *running;
    char *dev;
    Mac *attacker_mac;
    Mac *sender_mac;
    Ip *sender_ip;
    Mac *target_mac;
};

void *sendArpReply(void *args);
void *relayPacket(void *args);