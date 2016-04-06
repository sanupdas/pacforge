#include "pacforge.h"

char *progName; 
char errbuf[PCAP_ERRBUF_SIZE]; /* pcap error buffer */

void usageCommon(void);

int main(int argc, char **argv) 
{
    char *pn;
    int c;
    pcap_if_t *devList;
    int type = 0;
    char *device = NULL;
    int period = 0;
    uint16_t vlanId = 0;

    if ((pn = strrchr(argv[0], '/')) != NULL)
        progName = pn + 1;
    else
        progName = argv[0];

    if (argc < 2)
        usageCommon();
    
    while ((c = getopt(argc, argv, "LI:P:V:T:h")) != -1) {
        switch(c) {
            case 'L':
                if (pcap_findalldevs (&devList, errbuf) < 0)   
                {
                    fprintf (stderr, "%s", errbuf);
                    exit (1);
                }
                while (devList != NULL)
                {
                    printf ("%s\n", devList->name);
                    devList = devList->next;
                }
                break;
            case 'I':
                device = optarg;
                break;
            case 'P':
                period = atoi(optarg);
                break;
            case 'V':
                vlanId = atoi(optarg);
                if (vlanId <=0 || vlanId > 4095) {
                    printf("Invalid vlan identifier\n");
                    exit(-1);
                }
                break;
            case 'T':
                if (strcasecmp(optarg, "eth") == 0)
                //parse_eth_options(argc, argv);
                    type = ETH;
                else if (strcasecmp(optarg, "arp") == 0)
                //parse_arp_options(argc, argv);
                    type = ARP;
                else if (strcasecmp(optarg, "ip") == 0)
                //parse_ip_options(argc, argv);
                    type = IP;
                else if (strcasecmp(optarg, "icmp") == 0)
                //parse_icmp_options(argc, argv);
                    type = ICMP;
                else if (strcasecmp(optarg, "igmp") == 0)
                    parse_igmp_options(argc, argv, 
                                       vlanId, device, period);
                //    type = IGMP;
                else if (strcasecmp(optarg, "tcp") == 0)
                //parse_tcp_options(argc, argv);
                    type = TCP;
                else if (strcasecmp(optarg, "udp") == 0)
                //parse_udp_options(argc, argv);
                    type = UDP;
                else
                    printf("invalid packet type\n");

                //parse_packet_options(argc, argv);
                break;
            case 'h':
            default:
                usageCommon();
                break;
        }
    }

    return 0;
}

void sendPacket(uint8_t *pkt, int pktLen, char *device, int period) 
{
    pcap_t *ppcap = NULL;

    /*
     * Finally, we have the packet and are ready to inject it.
     * First, we open the interface we want to inject on using pcap.
     */
    ppcap = pcap_open_live(device, ETHER_MAX_LEN, 1, 1000, errbuf);

    if (ppcap == NULL) {
        printf("Could not open interface wlan0 for packet injection: %s", errbuf);
        return;
    }

    /*
     * Then we send the packet and clean up after ourselves
     */

    do {
        if (pcap_sendpacket(ppcap, pkt, pktLen) == -1) {
            pcap_close(ppcap);
            return;
        }
        if (period) {
            usleep( period * 1000 );
        }
    } while (period);

    /*
     * If something went wrong, let's let our user know
     */
    pcap_perror(ppcap, "Failed to inject packet");
    pcap_close(ppcap);
}

void getMacAddr(char *ifname, char *macaddrstr) {
    struct ifaddrs *ifap, *ifaptr;
    unsigned char *ptr;

    if (getifaddrs(&ifap) == 0) {
        for(ifaptr = ifap; ifaptr != NULL; ifaptr = (ifaptr)->ifa_next) {
            if (!strcmp((ifaptr)->ifa_name, ifname) && (((ifaptr)->ifa_addr)->sa_family == AF_LINK)) {
                ptr = (unsigned char *)LLADDR((struct sockaddr_dl *)(ifaptr)->ifa_addr);
                sprintf(macaddrstr, "%02x:%02x:%02x:%02x:%02x:%02x",
                        *ptr, *(ptr+1), *(ptr+2), *(ptr+3), *(ptr+4), *(ptr+5));
                break;
            }
        }
        freeifaddrs(ifap);
    }
}

unsigned short int
calculateChecksum(uint8_t* buffer, int len) 
{
    unsigned long int chkSum = 0;
    unsigned short int *ptr = (unsigned short int *) buffer;

    while (len > 1) {
        chkSum += *ptr++;
        len -= 2;
    }

    if ( len > 0 ) {
#if (BYTE_ORDER == BIG_ENDIAN)
        chkSum += (*ptr & 0xff00);
#else
        chkSum += (*ptr & 0x00ff);
#endif
    }
    chkSum = (chkSum & 0xffff) + (chkSum >> 16);
    chkSum = (chkSum & 0xffff) + (chkSum >> 16);
    return ((unsigned short int)((~chkSum) & 0xffff));
}

void usageCommon() {
    (void)fprintf(stderr, "%s version %s\n"
            "%s\n"
            "Usage: %s [-L] [-I interface] [-P period] [-V vid]\n"
            "               [-T type] [-h]\n"
            "\nOptions:\n"
            " -L              Print a list of network interfaces available.\n"
            " -I ifname       Interface to send pcap packet.\n"
            " -P period       Send packet periodicaly (in ms)\n"
            " -T type         Packet type to be send (eth, ip, ipv6, tcp, udp," 
                              " icmp, igmp, mld, arp)\n"
            " -h              Print usage.\n\n",
        progName, VERSION, pcap_lib_version(), progName);
    exit(EXIT_SUCCESS);
}

