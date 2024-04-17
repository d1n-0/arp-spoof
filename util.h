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
};
#pragma pack(pop)

int getMacFromInterface(char* dev, Mac* mac);
int getIpFromInterface(char* dev, Ip* ip);
int getMacFromIP(char* dev, Mac* smac, Ip* sip, Ip* tip, Mac* tmac);