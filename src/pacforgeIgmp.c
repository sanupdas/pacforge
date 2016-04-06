#include "pacforge.h"

#define IN_ROUTER_ALERT_OPT    (u_int32_t)0x94040000

typedef struct {
    struct ip  iph;
    u_int32_t  routerOpt;
    struct igmphdr igmph;
} __attribute((packed)) IgmpPacket;


typedef struct {
    struct ether_header eth;
    IgmpPacket igmp;
} __attribute((packed)) EthFullPacket;

typedef struct {
    struct ether_header eth;
    uint16_t vlan_control;
    uint16_t vlan_protocol;
    IgmpPacket igmp;
} __attribute((packed)) VlanFullPacket;

static void
getMulticastMacFromIp(uint8_t* macAddr, u_int32_t grpAddr)
{
    uint8_t* ipAddrPtr;

    ipAddrPtr = (uint8_t*)&grpAddr;
    macAddr[0] = 0x01;
    macAddr[1] = 0x00;
    macAddr[2] = 0x5E;
    macAddr[3] = ipAddrPtr[1] & 0x7F;
    macAddr[4] = ipAddrPtr[2];
    macAddr[5] = ipAddrPtr[3];
}

static void
buildIgmpPacket(struct ether_header* eth, char* srcMacAddr, uint16_t ethType,
        IgmpPacket* pkt,  u_int32_t srcAddr, u_int32_t grpAddr, uint8_t igmpType)
{
    u_int32_t dstAddr;
    u_int32_t ipv4AllRouterMcastAddr =  htonl(0xe0000002);
    u_int32_t ipv4AllNodeMcastAddr = htonl(0xe0000001);

    // Determinate the destination IP address
    if (igmpType == IGMP_V2_LEAVE_GROUP) {
        dstAddr = ipv4AllRouterMcastAddr;
    } else  if ((igmpType == IGMP_MEMBERSHIP_QUERY) && (!grpAddr)) {
        dstAddr = ipv4AllNodeMcastAddr;
    } else {
        dstAddr = grpAddr;
    }

    // Build ethernet header
    memcpy(eth->ether_shost, srcMacAddr, ETHER_ADDR_LEN);
    getMulticastMacFromIp(eth->ether_dhost, dstAddr);
    eth->ether_type = htons(ethType);

    // Build the IPv4 header
    pkt->iph.ip_hl = 6;
    pkt->iph.ip_v = 4;
    pkt->iph.ip_tos = 0;
    pkt->iph.ip_len = htons(sizeof(IgmpPacket));
    pkt->iph.ip_id = htons(1);
    pkt->iph.ip_off = 0;
    pkt->iph.ip_ttl = 1;
    pkt->iph.ip_p = IPPROTO_IGMP;
    pkt->iph.ip_sum = 0;
    pkt->iph.ip_src.s_addr = srcAddr;
    pkt->iph.ip_dst.s_addr = dstAddr;

    // Put router option
    pkt->routerOpt = htonl( IN_ROUTER_ALERT_OPT );

    // Build IGMP
    pkt->igmph.type = igmpType;
    if (igmpType == IGMP_MEMBERSHIP_QUERY) {
        pkt->igmph.code = grpAddr?10:100;
    } else {
        pkt->igmph.code = 0;
    }
    pkt->igmph.checksum = 0;
    pkt->igmph.group.s_addr = grpAddr;

    // Build IGMP checksum
    pkt->igmph.checksum = calculateChecksum((uint8_t *)&pkt->igmph,
            sizeof(struct igmphdr));

    // Build the IP checksum
    pkt->iph.ip_sum = calculateChecksum((uint8_t*)&pkt->iph, 24);
}

void
usage(void)
{
    printf("Usage : igmp  [options] <commands>\n");
    printf("Options:\n");
    printf("   -s srcIpAddr    provide the source IP address\n");
    printf("   -r mcgroup      send a report to the provided multicast group\n");
    printf("   -l mcgroup      send a leave to the provided multicast group\n");
    printf("   -g              send a general query\n");
    printf("   -q mcgroup      send a group specific query\n");
    exit(-1);
}

void parse_igmp_options(int argc, char **argv, 
                        uint16_t vlanId, char *device, int period) {

    int i;
    u_int32_t grpAddr;
    u_int32_t srcAddr;
    int result;
    int igmpType = IGMP_MEMBERSHIP_QUERY;
    EthFullPacket ethPkt;
    VlanFullPacket vlanPkt;
    char macaddrstr[6];
    int opt_srcAddr = 0;
    int opt_grpAddr = 0;
    int opt_report = 0;
    int opt_leave = 0;
    int opt_query = 0;
    uint8_t *pkt = NULL;
    int pktLen = 0;

    while ((i = getopt(argc, argv, "s:r:l:gq:h")) != -1) {
        switch (i) {
            case 's':
                result = inet_pton(AF_INET, optarg, &srcAddr);
                if (result <=0) {
                    printf("Invalid source address\n");
                    exit(-1);
                }
                opt_srcAddr = 1;
                break;
            case 'r':
                result = inet_pton(AF_INET, optarg, &grpAddr);
                if (result <=0) {
                    printf("Invalid group address\n");
                    exit(-1);
                }
                igmpType = IGMP_V2_MEMBERSHIP_REPORT;
                opt_grpAddr = 1;
                opt_report = 1;
                break;
            case 'l':
                result = inet_pton(AF_INET, optarg, &grpAddr);
                if (result <=0) {
                    printf("Invalid group address\n");
                    exit(-1);
                }
                igmpType = IGMP_V2_LEAVE_GROUP;
                opt_grpAddr = 1;
                opt_leave = 1;
                break;
            case 'q':
                result = inet_pton(AF_INET, optarg, &grpAddr);
                if (result <=0) {
                    printf("Invalid source address\n");
                    exit(-1);
                }
                igmpType = IGMP_MEMBERSHIP_QUERY;
                opt_grpAddr = 1;
                opt_query = 1; 
                break;
            case 'g':
                break;
            case 'h':
            default:
                usage();
                exit(-1);
        }
    }   

    if (!opt_srcAddr) {
        printf("** Source Address is required. **\n");
        usage();
        exit(-1);
    }

    if (opt_report || opt_leave || opt_query ) {
        if (!opt_grpAddr) {
            printf("**Multicast Group Address is required. **\n");
            usage();
            exit(-1);
        }
    }

    getMacAddr(device, macaddrstr);

    if (!vlanId) {
        buildIgmpPacket( &ethPkt.eth, macaddrstr, 0x0800,
                &ethPkt.igmp, srcAddr, grpAddr, igmpType);
        pktLen = sizeof(ethPkt);
        pkt = (uint8_t*)&ethPkt;

    } else {
        buildIgmpPacket( &vlanPkt.eth, macaddrstr, 0x8100,
                &vlanPkt.igmp, srcAddr, grpAddr, igmpType);

        vlanPkt.vlan_control = htons(vlanId & 0x0FFF);
        vlanPkt.vlan_protocol = htons(0x0800);
        pktLen = sizeof(vlanPkt);
        pkt = (uint8_t*)&vlanPkt;
    }
    sendPacket(pkt, pktLen, device, period);

    return;
}


