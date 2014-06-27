#ifndef STAMACH_H
#define STAMACH_H

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <pthread.h>
#include <string.h>
#include <signal.h>
#include <errno.h>
#include <stdint.h>
#include <pcap/pcap.h>
#include "http.h"

#define MAXBYTES 2048
#define IWINFO_BUFSIZE	24 * 1024

#ifndef sighandler_t
typedef void (*sighandler_t) (int);
#endif

struct stainfo{
    uint8_t mac[6];
    char machtype[20];
};

typedef struct statable{
	char *ifname;
	uint8_t mac[6];
	char machtype[20];
} STA_T;


int pcap_open(char * device, pcap_t **descr);
int stationtype(uint8_t *mac, char *interface, char *statype);
void * anly_packet(void *arg);
void * gtype_fn(void *arg);
int decodePacket(const u_char *pkt,uint32_t caplen,char *output);
int decodePacketfilter(const u_char *pkt,uint32_t caplen, const uint8_t *mac,char *output);
int httpdecode(const uint8_t *payload,uint32_t payloadLen,char *output);
int create_stafile(const char *filename, struct stainfo *sta, int len);
int search_mac(const char *filename, uint8_t *mac, char *buf);
int append_STA(STA_T *station);
struct stainfo* current_assoclist(const char *ifname, int *stalen);

#endif

