#include "stamach.h"
#include "iwinfo.h"


struct stainfo* current_assoclist(const char *ifname, int *stalen)
{
	const struct iwinfo_ops *iw;
	int i, len;
	char buf[IWINFO_BUFSIZE] = {0};
	struct stainfo *stations = NULL;
	struct stainfo *tmp = NULL;
	struct iwinfo_assoclist_entry *e = NULL;
	iw = iwinfo_backend(ifname);
	
	// get the device ifname operation handler
	if (!iw)
	{
		fprintf(stderr, "No such wireless device:%s\n", ifname);
		return NULL;
	}

	if (iw->assoclist(ifname, buf, &len))
	{
		fprintf(stderr, "No information available\n");
		return NULL;
	}
	else if (len <= 0)
	{
		fprintf(stderr, "No station connected\n");
		return NULL;
	}

	*stalen = len / sizeof(struct iwinfo_assoclist_entry);
	stations = (struct stainfo *)calloc(len, sizeof(struct stainfo));
	tmp = stations;
	
	for (i = 0; i < len; i += sizeof(struct iwinfo_assoclist_entry))
	{
		e = (struct iwinfo_assoclist_entry *) &buf[i];
		memcpy(tmp->mac, e->mac, 6);
		tmp++;
	}

	return stations;
}
