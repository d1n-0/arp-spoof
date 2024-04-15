#include "util.h"

int getMacFromInterface(char* dev, Mac* mac) {
    if (dev == NULL) {
        fprintf(stderr, "dev is NULL\n");
        return -1;
    }

    if (strlen(dev) >= IFNAMSIZ) {
        fprintf(stderr, "dev name is too long\n");
        return -1;
    }

    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        perror("socket");
        return -1;
    }

    struct ifreq ifr;
    strncpy(ifr.ifr_name, dev, IFNAMSIZ);

    if (ioctl(sock, SIOCGIFHWADDR, &ifr) < 0) {
        perror("ioctl");
        close(sock);
        return -1;
    }

    close(sock);

    *mac = Mac((uint8_t *)ifr.ifr_hwaddr.sa_data);
    return 0;
}

int getIpFromInterface(char* dev, Ip* ip) {
    if (dev == NULL) {
        fprintf(stderr, "dev is NULL\n");
        return -1;
    }

    if (strlen(dev) >= IFNAMSIZ) {
        fprintf(stderr, "dev name is too long\n");
        return -1;
    }

    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        perror("socket");
        return -1;
    }

    struct ifreq ifr;
    strcpy(ifr.ifr_name, dev);

    if (ioctl(sock, SIOCGIFADDR, &ifr) < 0) {
        perror("ioctl");
        close(sock);
        return -1;
    }

    close(sock);

    *ip = Ip(inet_ntoa(((struct sockaddr_in*)&ifr.ifr_addr)->sin_addr));
    return 0;
}

int getMacFromIP(char* dev, Mac* smac, Ip* sip, Ip* tip, Mac* tmac) {
    if (dev == NULL) {
        fprintf(stderr, "dev is NULL\n");
        return -1;
    }

    if (strlen(dev) >= IFNAMSIZ) {
        fprintf(stderr, "dev name is too long\n");
        return -1;
    }

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
    if (handle == nullptr) {
        fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
        return -1;
    }

    EthArpPacket packet;

    packet.eth_.dmac_ = Mac("ff:ff:ff:ff:ff:ff");
    packet.eth_.smac_ = *smac;
    packet.eth_.type_ = htons(EthHdr::Arp);

    packet.arp_.hrd_ = htons(ArpHdr::ETHER);
    packet.arp_.pro_ = htons(EthHdr::Ip4);
    packet.arp_.hln_ = Mac::SIZE;
    packet.arp_.pln_ = Ip::SIZE;
    packet.arp_.op_ = htons(ArpHdr::Request);
    packet.arp_.smac_ = *smac;
    packet.arp_.sip_ = htonl(*sip);
    packet.arp_.tmac_ = Mac("00:00:00:00:00:00");
    packet.arp_.tip_ = htonl(*tip);

    int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
    if (res != 0) {
        fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
        return -1;
    }

    while (true) {
        struct pcap_pkthdr* header;
        const u_char* packet;
        int res = pcap_next_ex(handle, &header, &packet);
        if (res == 0) continue;
        if (res == -1 || res == -2) {
            fprintf(stderr, "pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
            return -1;
            break;
        }

        EthHdr* eth = (EthHdr*)packet;
        if (eth->type() != EthHdr::Arp) continue;

        ArpHdr* arp = (ArpHdr*)(packet + sizeof(EthHdr));
        if (arp->op() != ArpHdr::Reply) continue;
        if (arp->hrd() != ArpHdr::ETHER) continue;
        if (arp->pro() != EthHdr::Ip4) continue;
        if (htonl(arp->sip()) != htonl(*tip)) continue;

        *tmac = arp->smac();
        break;
    }

    return 0;
}
