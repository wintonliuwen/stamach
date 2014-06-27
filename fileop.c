#include "stamach.h"

/*int append_info(const char *filename, struct stainfo sta)
{
	char command[40] = {0};
	uint8_t *stamac = sta.mac;
	int ret = 0;
	sprintf(command, "grep %02x:%02x:%02x:%02x:%02x:%02x %s", stamac[0], stamac[1], stamac[2], stamac[3], stamac[4], stamac[5], filename);
	ret = system(command);

}
*/


int create_stafile(const char *filename, struct stainfo *sta, int len)
{
	int i = 0;
	uint8_t *stamac = NULL;
	FILE *fp = fopen(filename, "w+");
    if (fp == NULL)
    {   
        printf("create file %s error:%s\n", filename, strerror(errno));
        return -1; 
    }   
	
	for (i = 0; i < len; i++)
	{
		stamac = sta->mac;
		if (sta->mac && strlen(sta->machtype) > 0)
		{
			fprintf(fp, "%02X:%02X:%02X:%02X:%02X:%02X  %s\n", stamac[0], stamac[1], stamac[2], stamac[3], stamac[4], stamac[5], sta->machtype);
		}
		sta++;
	}
	fclose(fp);
}

int append_STA(STA_T *station)
{
	char filename[20] = {0};
	FILE *fp = NULL;
	uint8_t *stamac = NULL;
	stamac = station->mac;
	sprintf(filename, "/tmp/%ssta", station->ifname);
	fp = fopen(filename, "a");
	if (fp == NULL)
	{
		printf("Open file %s error:%s\n", filename, strerror(errno));
		return -1;
	}
	
	fprintf(fp, "%02X:%02X:%02X:%02X:%02X:%02X  %s\n", stamac[0], stamac[1], stamac[2], stamac[3], stamac[4], stamac[5], station->machtype);
	fclose(fp);
	return 0;
}


// according the mac search machine type
int search_mac(const char *filename, uint8_t *mac, char *buf)
{
	FILE *read_fp = NULL;
	char command[80] = {0};
	sprintf(command, "grep %02X:%02X:%02X:%02X:%02X:%02X %s | awk '{print $2, $3}'", mac[0],mac[1],mac[2],mac[3],mac[4],mac[5], filename);
	read_fp = popen(command, "r");
    if (read_fp != NULL)
    {   
        fread(buf, sizeof(char), 20,read_fp);
        pclose(read_fp);
    }   
    else
    {   
        printf("execute %s error\n", filename);
        return -1; 
    } 
	if (strlen(buf) == 0)
	{
		return -1;
	}
	return 0;
}
