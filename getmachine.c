#include "stamach.h"
#include <time.h>
#include <sys/types.h>

#define PRINTMAC(a) printf("%02x:%02x:%02x:%02x:%02x:%02x", a[0], a[1], a[2], a[3], a[4], a[5])

/*
  Function: pcap_open
     device: the interface name to open ,for example "ath0"
     descr: the pcap_t to be used by caller.
  Return value: 0 on sucess, -1 on failure
*/
extern struct pcap_t *descr;

int pcap_open(char * device, pcap_t **descr)
{
    char errbuf[PCAP_ERRBUF_SIZE] = {0};
    if (device == NULL)
    {
        return -1;
    }

    *descr = pcap_open_live(device, MAXBYTES, 1, 0, errbuf);
    if (*descr == NULL)
    {
        printf("pcap_open_live error:%s\n", errbuf);
        return -1;
    }

    return 0;
}

void * anly_packet(void *arg)
{
	struct pcap_pkthdr pkthdr;
	STA_T sta_mach = *(STA_T *)arg;
	int i = 0;
	int expiredtimes = 0;
	int ret = 0;
	const uint8_t *packet = NULL;
	char *ifname = sta_mach.ifname;
	uint8_t *stamac = sta_mach.mac;
	char *buf = calloc(20, sizeof(char));
	char filename[20] = {0};
	pid_t tid = gettid();
	time_t now = time(NULL);

	free(arg);
	sprintf(filename, "/tmp/%ssta", ifname);
	while(1)
	{
		// capture and anlysis packets for 2 mins, it time is out then the thread exit
		if (expiredtimes%100 == 0)
		{
			if (time(NULL) - now >= 120)
				break;
		}
		packet = pcap_next(descr, &pkthdr);
		memset(buf, 0, 20);
		ret = decodePacketfilter(packet, pkthdr.len, stamac, buf);
		if (ret == HTTP_OK && strncmp(buf, "Other", 5))
		{
			break;
		}
		else if (ret == HTTP_OK && !strncmp(buf, "Other", 5))
		{
			i++;
			continue;
		}
		else if (ret == HTTP_FAIL)
		{
			expiredtimes++;
		}
	}
	
	if (strlen(buf) > 0)
	{
		memcpy(sta_mach.machtype, buf, strlen(buf)+1);
	}
	else{
		strcpy(sta_mach.machtype, "Other");
	}
	printf("anly_packet buf:%s\n", sta_mach.machtype);
	// if there is no data and the buf != Other
	memset(buf, 0, 20);
	ret = search_mac(filename, stamac, buf);
	if (ret < 0 && strncmp(sta_mach.machtype, "Other", 5))
	{
		append_STA(&sta_mach);
	}
	free(buf);
	printf("Thread %u exit\n", (unsigned int)tid);
	pthread_exit((void *)&sta_mach);
}


void * gtype_fn(void *arg)
{
	struct pcap_pkthdr pkthdr;
	STA_T sta_mach = *(STA_T *)arg;
	pcap_t *descr = NULL;
	int i = 0;
	int expiredtimes = 0;
	int ret = 0;
	const uint8_t *packet = NULL;
	char *ifname = sta_mach.ifname;
	uint8_t *stamac = sta_mach.mac;
	char *buf = calloc(20, sizeof(char));

	free(arg);
	
	if (pcap_open(ifname, &descr) < 0)
	{
		printf("open device %s error\n", ifname);
		return ((void *) 1);
	}
	
	while(1)
	{
		if (i >= 10 || expiredtimes >= 1000)
		{
			break;
		}
		packet = pcap_next(descr, &pkthdr);
		memset(buf, 0, 20);
		ret = decodePacketfilter(packet, pkthdr.len, stamac, buf);
		if (ret == HTTP_OK && strncmp(buf, "Other", 5))
		{
			break;
		}
		// if statype is "Other", then analysize 10 times
		else if (ret == HTTP_OK && !strncmp(buf, "Other", 5))
		{
			i++;
			continue;
		}
		else if (ret == HTTP_FAIL)
		{
			expiredtimes++;
		}
	}

	pcap_close(descr);	
	if (strlen(buf) > 0)
	{
		memcpy(sta_mach.machtype, buf, strlen(buf)+1);
	}
	else{
		strcpy(sta_mach.machtype, "Other");
	}
	free(buf);
	printf("gtype_fn buf:%s\n", sta_mach.machtype);
	append_STA(&sta_mach);

	pthread_exit((void *)&sta_mach);
}


int stationtype(uint8_t *mac, char *interface, char *statype)
{
	struct pcap_pkthdr pkthdr;
	int i = 0;
	int expiredtimes = 0;
	int losecount = 0;
	int ret = 0;
	const uint8_t *packet = NULL;
	char buf[20] = {0};
	pcap_t *descr = NULL;
	if (pcap_open(interface, &descr) < 0)
	{
		printf("open device %s error\n", interface);
		return -1;
	}
	
	while(1)
	{
		if (i >= 10 || expiredtimes >= 1000)
		{
			break;
		}
		packet = pcap_next(descr, &pkthdr);
		memset(buf, 0, 20);
		ret = decodePacketfilter(packet, pkthdr.len, mac, buf);
		// if statype is analysized sucessfully, break the while loop
		if (ret == HTTP_OK && strncmp(buf, "Other", 5))
		{
			break;
		}
		// if statype is "Other", then analysize 10 times
		else if (ret == HTTP_OK && !strncmp(buf, "Other", 5))
		{
			i++;
			printf("i:%d buf:%s\n",i, buf);
			continue;
		}
		else if (ret == HTTP_FAIL)
		{
			expiredtimes++;
		}
	//	if (pkthdr.len > 0)
	//		printf("mac %02x:%02x:%02x:%02x:%02x:%02x\n", packet[0], packet[1], packet[2], packet[3], packet[4], packet[5]);
//		PRINTMAC(packet);
	}
	
	pcap_close(descr);	
	if (strlen(buf) > 0)
	{
		memcpy(statype, buf, strlen(buf)+1);
	}
	else{
		strcpy(statype, "Other");
	}
	printf("stationtype result:%s\n", statype);
	return 0;
}

