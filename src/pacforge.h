#ifndef __PACFORGE_H__
#define __PACFORGE_H__

#include "def.h"

void parse_igmp_options(int, char **,
                        uint16_t, char *, int);

void getMacAddr(char *, char *);

unsigned short int
calculateChecksum(uint8_t *, int);
void sendPacket(uint8_t *pkt, int pktLen, char *device, int period);

#endif /* __PACFORGE_H__ */
