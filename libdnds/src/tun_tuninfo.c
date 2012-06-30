/*
 * tun_tuninfo.c: BSD tun/tap API
 *
 * Copyright (C) 2009 Nicolas Bouliane
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; version 2
 * of the License.
 *
 */

#include <sys/types.h>

#include <sys/socket.h> // AF_MAX
#include <net/if.h>
#include <net/if_types.h>
#include <net/if_tun.h>

#include <fcntl.h>

#include "tun.h"
#include "journal.h"

extern int tun_destroy(iface_t *tun)
{
	char sys[128];
	int ret;

	ret = close(tun->fd);
	if (ret == -1) {
		jlog(L_WARNING, "tun_tuninfo]> failed closing iface fd [%i] :: %i:%s", __LINE__, __FILE__);
	}

	snprintf(sys, 128, "ifconfig %s destroy",
		tun->devname);

	jlog(L_DEBUG, "tun_tuninfo]> sys:: %s", sys);

	ret = system(sys);

	return ret;
}

extern int tun_up(char *devname, char *addr)
{
	char sys[128];
	int ret;

	snprintf(sys, 128, "ifconfig %s %s link0",
		devname,
		addr);

	jlog(L_DEBUG, "tun_tuninfo]> sys:: %s", sys);
	ret = system(sys);

	return ret;
}

extern int tun_create(char *devname, int *fd)
{
	char name[255];
	int ret;
	int dev;

	struct tuninfo info;

	for (dev = 255; dev >= 0; (dev)--) {
		snprintf(name, sizeof(name), "/dev/tun%i", dev);
		*fd = open(name, O_RDWR);

		if (*fd >= 0)
			break;
	}

	snprintf(devname, IFNAMSIZ, "%s", name+5);

	/* Flags given will be set; flags omitted will be cleared; */
	ret = ioctl(*fd, TUNGIFINFO, &info);
	if (ret < 0) {
		jlog(L_ERROR, "tun_tuninfo]> ioctl TUNGIFINFO failed %s :: %s:%i", name, __FILE__, __LINE__);
		close(*fd);
		return -1;
	}
	/* Layer 2 tunneling mode */
	info.flags = IFF_UP | IFF_BROADCAST;
	info.type = IFT_ETHER;
	ret = ioctl(*fd, TUNSIFINFO, &info);
	if (ret < 0) {
		jlog(L_ERROR, "tun_tuninfo]> ioctl TUNSIFINFO failed %s :: %s:%i", name, __FILE__, __LINE__);
		close(*fd);
		return -1;
	}

	return 0;
}
