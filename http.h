
/*****************http.c**************/
#ifndef _HTTP_H
#define _HTTP_H

#include <stdio.h>
#include <netinet/in.h>
#include <netinet/ip6.h> 
#include <netinet/tcp.h>
#include <netinet/ip.h>

#define LINELENGTH 1024
#define HTTP_FAIL -1
#define HTTP_OK    1

#define ETHERTYPE_IP    0x0800
#define ETHERTYPE_IPV6  0x08dd

#if 0
typedef unsigned int 		uint32_t;
typedef unsigned long int   uint64_t;
typedef unsigned char 		uint8_t;
typedef unsigned short      uint16_t;
#endif

typedef struct __HTTP_USERAGENT_T_
{
	uint8_t OS[LINELENGTH];
	uint8_t BrowerType[LINELENGTH];
}httpUserAgent;

enum _http_ver
{
	HTTP_VER_1_0 = 0,
	HTTP_VER_1_1,
	HTTP_VER_NONE
};
typedef enum  _http_ver http_ver;


typedef enum _http_mthd http_mthd;
enum _http_mthd 
{
    HTTP_MT_OPTIONS = 0, /* RFC2616 */
    HTTP_MT_GET,
    HTTP_MT_HEAD,
    HTTP_MT_POST,
    HTTP_MT_PUT,
    HTTP_MT_DELETE,
    HTTP_MT_TRACE,
    HTTP_MT_CONNECT,
    HTTP_MT_PATCH,
    HTTP_MT_LINK,
    HTTP_MT_UNLINK,
    HTTP_MT_PROPFIND,    /* RFC2518 */
    HTTP_MT_MKCOL,
    HTTP_MT_COPY,
    HTTP_MT_MOVE,
    HTTP_MT_LOCK,
    HTTP_MT_UNLOCK,
    HTTP_MT_POLL,        /* Outlook Web Access */
    HTTP_MT_BCOPY,
    HTTP_MT_BMOVE,
    HTTP_MT_SEARCH,
    HTTP_MT_BDELETE,
    HTTP_MT_PROPPATCH,
    HTTP_MT_BPROPFIND,
    HTTP_MT_BPROPPATCH,
    HTTP_MT_LABEL,             /* RFC 3253 8.2 */
    HTTP_MT_MERGE,             /* RFC 3253 11.2 */
    HTTP_MT_REPORT,            /* RFC 3253 3.6 */
    HTTP_MT_UPDATE,            /* RFC 3253 7.1 */
    HTTP_MT_CHECKIN,           /* RFC 3253 4.4, 9.4 */
    HTTP_MT_CHECKOUT,          /* RFC 3253 4.3, 9.3 */
    HTTP_MT_UNCHECKOUT,        /* RFC 3253 4.5 */
    HTTP_MT_MKACTIVITY,        /* RFC 3253 13.5 */
    HTTP_MT_MKWORKSPACE,       /* RFC 3253 6.3 */
    HTTP_MT_VERSION_CONTROL,   /* RFC 3253 3.5 */
    HTTP_MT_BASELINE_CONTROL,  /* RFC 3253 12.6 */
    HTTP_MT_NOTIFY,            /* uPnP forum */
    HTTP_MT_SUBSCRIBE,
    HTTP_MT_UNSUBSCRIBE,
    HTTP_MT_ICY,               /* Shoutcast client (forse) */
    HTTP_MT_NONE
};

struct ether_header
{
	uint8_t     ether_dhost[6];
	uint8_t 	ether_shost[6];
	uint16_t 	ether_type; 
};

#if 0
struct ip6_hdr 
{
	union 
	{
		struct ip6_hdrctl 
		{
			uint32_t ip6_un1_flow; /* 24 bits of flow-ID */
			uint16_t ip6_un1_plen; /* payload length */
			uint8_t ip6_un1_nxt; /* next header */
			uint8_t ip6_un1_hlim; /* hop limit */
		} ip6_un1;
		uint8_t ip6_un2_vfc; /* 4 bits version, 4 bits priority */
	} ip6_ctlun;
	struct in6_addr ip6_src; /* source address */
	struct in6_addr ip6_dst; /* destination address */
};

#define ip6_vfc ip6_ctlun.ip6_un2_vfc
#define ip6_flow ip6_ctlun.ip6_un1.ip6_un1_flow
#define ip6_plen ip6_ctlun.ip6_un1.ip6_un1_plen
#define ip6_nxt ip6_ctlun.ip6_un1.ip6_un1_nxt
#define ip6_hlim ip6_ctlun.ip6_un1.ip6_un1_hlim

#define ip6_hops ip6_ctlun.ip6_un1.ip6_un1_hlim
#endif

#endif
