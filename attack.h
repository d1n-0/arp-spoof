#pragma once

#include <cstdio>
#include <pcap.h>

#include <thread>
#include <queue>
#include <vector>
#include <map>
#include <utility>
#include <condition_variable>

#include "ethhdr.h"
#include "arphdr.h"
#include "iphdr.h"
#include "util.h"

using IpPair = std::pair<uint32_t, uint32_t>;
using IpMap = std::map<IpPair, int>;
using Packet = const u_char*;
using PacketQueue = std::queue<std::pair<Packet, int>>;

void *arp_infect(
    char *dev, Mac *attacker_mac, Ip *attacker_ip, Mac *sender_mac, Ip *sender_ip, Mac *target_mac, Ip *target_ip,
    volatile bool *running
);
void *relay_packet(
    char *dev, Mac *attacker_mac, Mac *sender_mac, Ip *sender_ip, Mac *target_mac,
    int sender_to_target_idx, int target_to_sender_idx,
    std::vector<PacketQueue> *packet_queue,
    volatile bool *running,
    std::mutex *m, std::condition_variable *cv
);
void *receive_packet(
    char *dev,
    volatile bool *running,
    std::vector<PacketQueue> *packet_queue, IpMap *ip_map,
    std::mutex *m, std::condition_variable *cv
);
