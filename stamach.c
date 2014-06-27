#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include "stamach.h"
#include <sys/syscall.h>

#define WLAN0 "wlan0"
#define WLAN1 "wlan1"
#define WLAN0FILE "/tmp/wlan0sta"
#define WLAN1FILE "/tmp/wlan1sta"

pid_t gettid()
{
     return syscall(SYS_gettid);
}

struct pcap_t *descr = NULL;

sighandler_t rsignal(int signo, sighandler_t func)
{
	struct sigaction act,oact;
	act.sa_handler = func;
	sigemptyset(&act.sa_mask);
	act.sa_flags = 0;
	if (signo == SIGALRM)
	{
		#ifdef SA_INTERRUPT
			act.sa_flags |= SA_INTERRUPT;
		#endif
	}
	else
	{
		#ifdef SA_RESTART
			act.sa_flags |= SA_RESTART;
		#endif
	}
	if (sigaction(signo, &act, &oact) < 0)
	{
		return(SIG_ERR);
	}
	return(oact.sa_handler);
}


static void sig_getmachine(int signo);

int main(int argc, char **argv)
{

	if (pcap_open(WLAN0, &descr) < 0)
    {
		printf("open device %s error\n", WLAN0);
		return; 
	}

	if (rsignal(SIGINT, SIG_DFL) == SIG_ERR)
	{
		printf("sig SIG_DFL error\n");
		return -1;
	}

	if (rsignal(SIGUSR1, sig_getmachine) == SIG_ERR)
	{
		printf("sig SIGUSR1 error\n");
		return -1;
	}

	while(1)
		pause();

}

static void sig_getmachine(int signo)
{
	struct stainfo *stalist;
	int i, len, ret;
	char buf[20] = {0};

// Don't block when the handler is still run
	sigset_t set;
	sigemptyset(&set);
	sigaddset(&set, signo);

    if (sigprocmask(SIG_UNBLOCK,&set, NULL) < 0)
    {
        printf("sigprocmask error\n");
    }
    else
		printf("sigprocmask succeed\n");

	printf("catch signal %d\n", signo);
	
	// step1: Get associated stations

	stalist = current_assoclist(WLAN0, &len);
	if (stalist == NULL)
	{
		return;
	}
	// step2: open wireless interface device


	for (i = 0; i < len; i++)
	{
		STA_T *onestation = calloc(1, sizeof(STA_T));
		pthread_t *tid = NULL;
		onestation->ifname = WLAN0;
		memcpy(onestation->mac, stalist[i].mac, 6);

	// step3: search the table
		memset(buf, 0, 20);
		ret = search_mac(WLAN0FILE, stalist[i].mac, buf);
  		// it's already has station type
		if (ret == 0 && strncmp(buf, "Other", 5))
		{
			strcpy(stalist[i].machtype, buf);
			continue;
		}

		tid = calloc(1, sizeof(pthread_t));
	// step4: analysis the 
		if (pthread_create(&tid, NULL, anly_packet, (void *)onestation) != 0)
		{
			fprintf(stderr, "can't create thread anly_packet\n");
		}
//		free(onestation);
		free(tid);
	}
	free(stalist);

}
