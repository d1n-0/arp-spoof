#pragma once

#include <sys/ioctl.h>
#include <net/if.h>
#include <unistd.h>
#include <netinet/in.h>
#include <string.h>
#include <stdio.h>
#include <string>
#include <pcap.h>
#include "ethhdr.h"
#include "arphdr.h"
#include "mac.h"
#include "ip.h"

#pragma pack(push, 1)
struct EthArpPacket final {
    EthHdr eth_;
    ArpHdr arp_;
    EthArpPacket(Mac eth_dmac, Mac eth_smac, uint16_t op, Mac arp_smac, Ip sip, Mac arp_tmac, Ip tip)
    {
        eth_.dmac_ = eth_dmac;
        eth_.smac_ = eth_smac;
        eth_.type_ = htons(EthHdr::Arp);
        arp_.hrd_ = htons(ArpHdr::ETHER);
        arp_.pro_ = htons(EthHdr::Ip4);
        arp_.hln_ = Mac::SIZE;
        arp_.pln_ = Ip::SIZE;
        arp_.op_ = htons(op);
        arp_.smac_ = arp_smac;
        arp_.sip_ = htonl(sip);
        arp_.tmac_ = arp_tmac;
        arp_.tip_ = htonl(tip);
    }
};
#pragma pack(pop)

int getMacFromInterface(char* dev, Mac* mac);
int getIpFromInterface(char* dev, Ip* ip);
int getMacFromIP(char* dev, Mac* smac, Ip* sip, Ip* tip, Mac* tmac);