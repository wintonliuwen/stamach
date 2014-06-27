
/*Description:dethis program is decode http request message* 
 *in order to get user's OS and BrowerType                 *   
 *Author     :leiliang                                     *
 *Data       :2013-10-10                                   *
 *Mail       :leiliang.hunan@aliyun.com                    *
 *phone      :18652945536                                  *
 ***********************************************************/

#include <string.h>
#include <errno.h>
#include <time.h>
#include "pcap.h"
#include <pthread.h>
#include "http.h"
#include <math.h>
#include <malloc.h>
#include <stdlib.h>


#define DEBUG 1
#define filename "/tmp/mach.pl"



#define MACCOMPARE(src,dst) (src[0] == dst[0] &&\
								src[1] == dst[1] &&\
								src[2] == dst[2] &&\
								src[3] == dst[3] &&\
								src[4] == dst[4] &&\
								src[5] == dst[5])

int createfile(char *buf)
{
    FILE *fp = fopen(filename, "w+");
    if (fp == NULL)
    {
        printf("create file %s error:%s\n", filename, strerror(errno));
        return -1;
    }

    fprintf(fp, "use HTTP::UA::Parser;\n");
    fprintf(fp, "my $r = HTTP::UA::Parser->new(\"%s\");\n", buf);
    fprintf(fp, "print $r->device->family;");
    fclose(fp);
    return 0;

}

int anly_uagent(char *useragent, char *machtype)
{
    int ret = 0;
    FILE *read_fp = NULL;
    char command[30] = {0};
    if ( (ret = createfile(useragent)) < 0)
    {   
        return -1; 
    }   
    sprintf(command, "perl %s", filename);
    read_fp = popen(command, "r");
    if (read_fp != NULL)
    {
        fread(machtype, sizeof(char), 20,read_fp);
        pclose(read_fp);
    }
    else
    {
        printf("execute %s error\n", filename);
        return -1;
    }
    return 0;
}


/**********************************************************
Function Name  : 
Desrciption    :
Input          :
Output         :
Return         :
Author/Date    :
Note           :
Modify         :
**********************************************************/
int get_token_len(const char *linep, const char *lineend, const char **next_token)
{
	const char *tokenp;
	int token_len;

	tokenp = linep;

	while (linep != lineend && *linep != ' ' && *linep != '\r' && *linep != '\n')
	{
		linep++;	
	}
				
	token_len = linep - tokenp;

	while (linep != lineend && *linep == ' ')
	{									     
		linep++;	
	}
				
	*next_token = linep;
	
	return token_len;
}

/**********************************************************
Function Name  : 
Desrciption    :
Input          :
Output         :
Return         :
Author/Date    :
Note           :
Modify         :
**********************************************************/
static http_ver httpReqVersion(const char *line,int len)
{
	if ( !line || !len)
	{
		return HTTP_VER_NONE;
	}

	const char *next_token;
    const char *lineend;
	int tokenlen = 0; 

	lineend = line + len; 

    tokenlen = get_token_len(line,lineend,&next_token);

    if(tokenlen ==0 || line[tokenlen] != ' ')
	{		        
		return HTTP_VER_NONE;
	}

	line = next_token;

	tokenlen = get_token_len(line,lineend,&next_token);
	
    if(tokenlen ==0 || line[tokenlen] != ' ')
	{		        
		return HTTP_VER_NONE;
	}
	
	tokenlen = lineend - line;

	line = next_token;

	if (tokenlen == 0)
	{	
		return HTTP_VER_NONE;	
	}

    if (strncmp(line, "HTTP/1.0", 8) == 0)
	{
		return HTTP_VER_1_0;
	}

    if (strncmp(line, "HTTP/1.1", 8) == 0)
	{
		return HTTP_VER_1_1;
	}

	return HTTP_VER_NONE;	

}

/**********************************************************
Function Name  : 
Desrciption    :
Input          :
Output         :
Return         :
Author/Date    :
Note           :
Modify         :
**********************************************************/
const char *searchLineEnd(const char *data,const char *dataend,const uint8_t **eol)
{
	if ( !data || !dataend )
	{
		return NULL;
	}
	const char *lineend;
	
	lineend = memchr(data,'\n',dataend - data);
	if ( lineend == NULL )
	{
		lineend = dataend;
		*eol    = dataend;
	}
	else
	{
		if ( lineend != data )
		{
			if( *( lineend - 1 ) == '\r')
			{
				*eol = lineend - 1;
			}
			else
			{
				*eol = lineend;
				if ( lineend != ( dataend - 1 ) && *( lineend + 1 ) == '\r')
				{
					lineend ++;
				}
			}
		}
		else
		{
			*eol = lineend;
			if ( lineend != ( dataend - 1 ) && *( lineend + 1 ) == '\r')
			{
				lineend ++;
			}
		}
		lineend ++;
	}

	return lineend;
}

/**********************************************************
Function Name  :httpReqMethod
Desrciption    :获取所有的http请求的方法
Input          :
Output         :
Return         :http请求方法，如:get,post等，目前支持所有常用的方法
Author/Date    :leiliang/2013/10/10
Note           :
Modify         :
**********************************************************/
static http_mthd httpReqMethod(const char *data, int linelen)
{
	const char *ptr;
	int index = 0;
	int prefix_len = 0;
	char *unkn;


	if (linelen >= 2) 
	{
		if (strncmp(data, "M-", 2) == 0 || strncmp(data, "\r\n", 2) == 0) 
		{ 
			data += 2;
			linelen -= 2;
			prefix_len = 2;
		}
	}
	

	ptr = (const char *)data;
	while (index != linelen) 
	{
		if (*ptr == ' ')
		{
			break;
		}
		else 
		{
			ptr++;
			index++;
		}
	}

	switch (index) 
	{
	case 3:
		if (strncmp(data, "GET", index) == 0) 
		{
			return HTTP_MT_GET;
		}
		else if (strncmp(data, "PUT", index) == 0) 
		{
			return HTTP_MT_PUT;
		}
		break;

	case 4:
		if (strncmp(data, "COPY", index) == 0) 
		{
			return HTTP_MT_COPY;
		}
		else if (strncmp(data, "HEAD", index) == 0) 
		{
			return HTTP_MT_HEAD;
		}
		else if (strncmp(data, "LOCK", index) == 0) 
		{
			return HTTP_MT_LOCK;
		}
		else if (strncmp(data, "MOVE", index) == 0) 
		{
			return HTTP_MT_MOVE;
		}
		else if (strncmp(data, "POLL", index) == 0) 
		{
			return HTTP_MT_POLL;
		}
		else if (strncmp(data, "POST", index) == 0) 
		{
			return HTTP_MT_POST;
		}
		break;

	case 5:
		if (strncmp(data, "BCOPY", index) == 0) 
		{
			return HTTP_MT_BCOPY;
		}
		else if (strncmp(data, "BMOVE", index) == 0) 
		{
			return HTTP_MT_BMOVE;
		}
		else if (strncmp(data, "MKCOL", index) == 0) 
		{
			return HTTP_MT_MKCOL;
		}
		else if (strncmp(data, "TRACE", index) == 0) 
		{
			return HTTP_MT_TRACE;
		}
		else if (strncmp(data, "LABEL", index) == 0) 
		{ 
			return HTTP_MT_LABEL;
		}
		else if (strncmp(data, "MERGE", index) == 0) 
		{  
			return HTTP_MT_MERGE;
		}
		break;

	case 6:
		if (strncmp(data, "DELETE", index) == 0) 
		{
			return HTTP_MT_DELETE;
		}
		else if (strncmp(data, "SEARCH", index) == 0) 
		{
			return HTTP_MT_SEARCH;
		}
		else if (strncmp(data, "UNLOCK", index) == 0) 
		{
			return HTTP_MT_UNLOCK;
		}
		else if (strncmp(data, "REPORT", index) == 0) 
		{ 
			return HTTP_MT_REPORT;
		}
		else if (strncmp(data, "UPDATE", index) == 0) 
		{  
			return HTTP_MT_UPDATE;
		}
		else if (strncmp(data, "NOTIFY", index) == 0) 
		{
			return HTTP_MT_NOTIFY;
		}
		break;

	case 7:
		if (strncmp(data, "BDELETE", index) == 0) 
		{
			return HTTP_MT_BDELETE;
		}
		else if (strncmp(data, "CONNECT", index) == 0) 
		{
			return HTTP_MT_CONNECT;
		}
		else if (strncmp(data, "OPTIONS", index) == 0) 
		{
			return HTTP_MT_OPTIONS;
		}
		else if (strncmp(data, "CHECKIN", index) == 0) 
		{  
			return HTTP_MT_CHECKIN;
		}
		break;

	case 8:
		if (strncmp(data, "PROPFIND", index) == 0) 
		{
			return HTTP_MT_PROPFIND;
		}
		else if (strncmp(data, "CHECKOUT", index) == 0) 
		{ 
			return HTTP_MT_CHECKOUT;
		}

		break;

	case 9:
		if (strncmp(data, "SUBSCRIBE", index) == 0) 
		{
			return HTTP_MT_SUBSCRIBE;
		}
		else if (strncmp(data, "PROPPATCH", index) == 0) 
		{
			return HTTP_MT_PROPPATCH;
		}
		else  if (strncmp(data, "BPROPFIND", index) == 0) 
		{
			return HTTP_MT_BPROPFIND;
		}
		break;

	case 10:
		if (strncmp(data, "BPROPPATCH", index) == 0) 
		{
			return HTTP_MT_BPROPPATCH;
		}
		else if (strncmp(data, "UNCHECKOUT", index) == 0) 
		{  
			return HTTP_MT_UNCHECKOUT;
		}
		else if (strncmp(data, "MKACTIVITY", index) == 0) 
		{ 
			return HTTP_MT_MKACTIVITY;
		}
		break;

	case 11:
		if (strncmp(data, "MKWORKSPACE", index) == 0) 
		{  
			return HTTP_MT_MKWORKSPACE;
		}
		else if (strncmp(data, "UNSUBSCRIBE", index) == 0) 
		{
			return HTTP_MT_UNSUBSCRIBE;
		}

		break;

	case 15:
		if (strncmp(data, "VERSION-CONTROL", index) == 0) 
		{  
			return HTTP_MT_VERSION_CONTROL;
		}
		break;

	case 16:
		if (strncmp(data, "BASELINE-CONTROL", index) == 0) 
		{  
			return HTTP_MT_BASELINE_CONTROL;
		}
		break;

	default:
		break;
	
	}
}

/**********************************************************
Function Name  :httpdecode 
Desrciption    :解码http的请求报文，获取User-Agent字段，保存到httpUserAgent结构中
Input          :应用层数据指针，应用层数据长度
Output         :httpUserAgent结构体指针
Return         :返回HTTP_FAIL表示失败，HTTP_OK表示成功
Author/Date    :leiliang/2013/10/10
Note           :
Modify         :
*********************************************************/
static int httpdecode(const uint8_t *payload,uint32_t payloadLen, char *output)
{
	if ( !payload || !payloadLen || !output)
	{
		return HTTP_FAIL;
	}
	int ret = 0;
	const uint8_t *eol = NULL, *lineend = NULL;

	http_ver ver = HTTP_VER_NONE;
	http_mthd mth = HTTP_MT_NONE;
	uint32_t num = 0;
	char *endline = "\r\n",*type = NULL;
	char *str = NULL, *tmpstr = NULL, *useragent = NULL;
	char tmp[payloadLen + 1];
	memset(tmp,0x0,payloadLen + 1);
	uint8_t OS[LINELENGTH];
	memset(OS,0x0,LINELENGTH);
	uint8_t *p = NULL;
	lineend = searchLineEnd((const char *)payload,payload + payloadLen,&eol);

	if ( lineend != payload + payloadLen && (*eol == '\r' || *eol == '\n') )
	{
		ver = httpReqVersion((const char *)payload,lineend - payload);
		if ( ver != HTTP_VER_NONE )
		{
			mth = httpReqMethod(payload,lineend - payload);
		}
	}
	
	if ( mth != HTTP_MT_NONE )
	{
		/*
		 *decode useragent
		 */
		strncpy(tmp,payload,payloadLen);
		str = strtok(tmp,endline);
		if ( str == NULL )
		{
			return HTTP_FAIL;
		}
		while ( str != NULL )
		{
			if ( strncasecmp(str,"User-Agent: ",12)==0 )
			{
				tmpstr = strdup(str + 12);
			}
			str = strtok(NULL,endline);
		}
		if ( tmpstr == NULL )
		{
			return HTTP_FAIL;
		}

		type = tmpstr;
	
		while ( (*tmpstr) != '\0')
		{
			num ++;
			tmpstr ++;
		}
		
		useragent = (char *)malloc(num + 1);
		if ( !useragent )
		{
			return HTTP_FAIL;
		}
		memcpy(useragent,type,num);
		useragent[num] = '\0';
//#if 0
//		printf("useragent = %s\n",useragent);
		ret = anly_uagent(useragent, output);
		if (ret == 0)
		{
			if (!strncmp(output, "Other", 5))
			{
				printf("Other machine\n");
				printf("useragent = %s\n",useragent);
			}
			else
			{
				printf("machine:%s\n", output);
			}
			return HTTP_OK;
		}
		else
		{
			return HTTP_FAIL;
		}
		
//		printf("machtype:%s\n", machtype);
//#endif
#if 0
		p = strstr(useragent,"(");
		if ( p == NULL)
		{
			return HTTP_FAIL;
		}
		sscanf(p,"(%[^)]",OS);
		memcpy(output->OS,OS,LINELENGTH);
		
		if ( strstr(useragent,"MSIE") != NULL )
		{
			sprintf(output->BrowerType,"%s","MSIE");
		}
		else if ( strstr(useragent,"Chrome") != NULL)
		{
			sprintf(output->BrowerType,"%s","Chrome");
		}
		else if ( strstr(useragent,"Firefox") != NULL)
		{
			sprintf(output->BrowerType,"%s","Firefox");
		}
		else if ( strstr(useragent,"Safari") != NULL)
		{
			sprintf(output->BrowerType,"%s","Safari");
		}
		else if ( strstr(useragent,"Opera") != NULL)
		{
			sprintf(output->BrowerType,"%s","Opera");
		}	
		else if ( strstr(useragent,"Netscape") != NULL)
		{
			sprintf(output->BrowerType,"%s","Netscape");
		}
		else if ( strstr(useragent,"Navigator") != NULL)
		{
			sprintf(output->BrowerType,"%s","Navigator");
		}
		else
		{
			return HTTP_FAIL;
		}
		return HTTP_OK; 
#endif
	}
	else
	{
		return HTTP_FAIL;
	}
}
/**********************************************************
Function Name  :decodePacket
Desrciption    :解码ipv4和ipv6的数据包	
Input          :输入数据包结构指针libpcap形式，数据包的长度
Output         :输出对应的操作系统和浏览器信息
Return         :返回HTTP_FAIL表示失败，HTTP_OK表示成功
Author/Date    :雷亮/2013/20/10
Note           :
Modify         :
*********************************************************/
int decodePacket(const u_char *pkt,uint32_t caplen,
		char *output/**out the reference**/)
{
	if ( !pkt || !caplen || !output )
	{
		goto ERR;
	}
	uint32_t hlen = 0;/**ethernet head len****/
	uint32_t iphlen = 0,tcp_len = 0;
	uint16_t ether_type = 0, proto = 0;
	uint32_t payloadLen = 0;
	struct ether_header eth;
	struct iphdr  ipv4;
	struct ip6_hdr ipv6;
	struct tcphdr tcp;
	uint8_t *payload = NULL;
	uint32_t err = 0;
	uint16_t sport, dport;
	memset(&eth,0x0,sizeof(struct ether_header));
	
	hlen = sizeof(struct ether_header);
	
	if ( hlen > caplen )
	{
		goto ERR;
	}

	memcpy(&eth,(struct ether_header *)pkt,sizeof(struct ether_header));
	ether_type = ntohs(eth.ether_type);
	/*
	 * only process ethernet message
	 */
	if ( ether_type != ETHERTYPE_IP && ether_type != ETHERTYPE_IPV6 )
	{
		goto ERR;
	}
		
	switch( ether_type )
	{	
		case ETHERTYPE_IP:
			memcpy(&ipv4,pkt + hlen,sizeof(struct iphdr));
			if ( ipv4.version != 4)
			{
				goto ERR;
			}
			iphlen = ((uint16_t)ipv4.ihl * 4);/*ipv4 header len*/
			payloadLen = ntohs(ipv4.tot_len) - iphlen;
			proto = ipv4.protocol;
			
			if ( proto != IPPROTO_TCP )
			{
				goto ERR;
			}
		
			if ((caplen - hlen) < (iphlen + sizeof(struct tcphdr)))
			{
				goto ERR;
			}
			
			memcpy(&tcp,pkt + hlen + iphlen,sizeof(struct tcphdr));
			sport = ntohs(tcp.source);
			dport = ntohs(tcp.dest);
			tcp_len = (tcp.doff * 4);
			payloadLen -= tcp_len;
			payload = (uint8_t *)(pkt + hlen + iphlen + tcp_len);
			break;
		case ETHERTYPE_IPV6:
			memcpy(&ipv6,pkt + hlen,40);			
			if (((ipv6.ip6_vfc >> 4) & 0x0f) != 6 )
			{
				goto ERR;
			}
			
			iphlen = 40;
			payloadLen = ntohs(ipv6.ip6_plen);
			
			proto = ipv6.ip6_nxt;
			if ( proto != IPPROTO_TCP )
			{
				goto ERR;
			}
			
			memcpy(&tcp,pkt + hlen + iphlen,sizeof(struct tcphdr));
			sport = ntohs(tcp.source);
			dport = ntohs(tcp.dest);
			tcp_len = (tcp.doff * 4);
			payloadLen -= tcp_len;
			payload = (uint8_t *)(pkt + hlen + iphlen + tcp_len);			
			break;
		default:
			goto ERR;
	}

	if ( sport != 80 && dport != 80 )
	{
		goto ERR;
	}
	err = httpdecode(payload,payloadLen,output);
	if ( err == HTTP_FAIL)
	{
		goto ERR;
	}
	else
	{
		return HTTP_OK;
	}

ERR:
	return HTTP_FAIL;
}

/**********************************************************
Function Name  :decodePacketfilter
Desrciption    :过滤mac地址调用解码函数	
Input          :输入数据包结构指针libpcap形式，数据包的长度，以及需要过滤的mac地址
Output         :输出对应的操作系统和浏览器信息
Return         :返回HTTP_FAIL表示失败，HTTP_OK表示成功
Author/Date    :雷亮/2013/10/11
Note           :
Modify         :
*********************************************************/
int decodePacketfilter(const u_char *pkt,uint32_t caplen, const uint8_t *mac,char *output)
{
	if ( !pkt || !caplen || !output )
	{
		return HTTP_FAIL;
	}
	struct ether_header eth;
	uint32_t err = 0, index,matched = 0;
	memset(&eth,0x0,sizeof(struct ether_header));
	uint16_t ether_type = 0;
	uint32_t hlen = 0;/**ethernet head len****/

	hlen = sizeof(struct ether_header);
	
	if ( hlen > caplen )
	{
		return HTTP_FAIL;
	}

	memcpy(&eth,(struct ether_header *)pkt,sizeof(struct ether_header));
	ether_type = ntohs(eth.ether_type);
	/*
	 * only process ethernet message
	 */	
	if ( ether_type != ETHERTYPE_IP && ether_type != ETHERTYPE_IPV6 )
	{
		return HTTP_FAIL;
	}

 
	matched = MACCOMPARE(mac,eth.ether_dhost) || MACCOMPARE(mac,eth.ether_shost);

	if ( matched == HTTP_OK )
	{
		err = decodePacket(pkt,caplen,output);
		return err;
	}
	else
	{
		return HTTP_FAIL;
	}
	return HTTP_FAIL;
}

#if 0
#ifdef DEBUG
void my_callback(u_char *user,const struct pcap_pkthdr *h,const u_char *pkt_data )
{
	int err = 0;
	httpUserAgent *output = (httpUserAgent *)malloc(sizeof(httpUserAgent));
	char *macaddr = "3c970e958520"; 
	if ( !output )
	{
		printf("malloc failed\r\n");
		return;
	}
	memset(output,0x0,sizeof(httpUserAgent));
	err = decodePacket(pkt_data,h->caplen,macaddr,output);
	if ( err == HTTP_OK )
	{
		printf("OS = %s\n",output->OS);
		printf("UA = %s\n",output->BrowerType);
	}
}

int main(int argc,char *argv[])
{
	pcap_t *pt;
	char *dev;
	char errbuf[128];
	int ret = 0;
	const u_char *packet;
	dev = pcap_lookupdev(errbuf);

	if ( dev == NULL )
	{
		printf("%s\r\n",errbuf);
		exit(1);
	}

	pt = pcap_open_live(dev,BUFSIZ,0,-1,errbuf);

	if ( pt == NULL )
	{
		printf("error = %s\r\n",errbuf);
	}

	pcap_loop(pt,-1,my_callback,NULL);

	return 0;

}

#endif
#endif
