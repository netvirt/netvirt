/*
 * tun_ifreq.c: linux tun/tap API
 *
 * Copyright (C) 2009 Nicolas Bouliane
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; version 2
 * of the License.
 *
 */

#include <sys/ioctl.h>
#include <sys/socket.h>

#include <linux/if.h>
#include <linux/if_tun.h>

#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "journal.h"
#include "tun.h"

/* TODO
 * implement tun_destroy
 */

extern int tun_destroy(iface_t *iface)
{
	return -1;
}

extern int tun_up(char *devname, char *addr)
{
	char sys[128];
	int ret;

	snprintf(sys, 128, "%s %s %s",
		"ifconfig",
		devname,
		addr);

	jlog(L_DEBUG, "tun_ifreq]> sys:: %s", sys);

	ret = system(sys);
	return ret;
}

extern int tun_create(char *devname, int *fd)
{
	struct ifreq ifr;
	int ret;
	int dev;

	*fd = open("/dev/net/tun", O_RDWR);
	if (*fd < 0) {
		jlog(L_ERROR, "tun_ifreq]> open tun failed :: %s:%i", __FILE__, __LINE__);
		return -1;
	}

	memset(&ifr, 0, sizeof(ifr));
	ifr.ifr_flags = IFF_TAP | IFF_NO_PI;
	ifr.ifr_name[0] = '\0';	/* Get the next available interface */

	ret = ioctl(*fd, TUNSETIFF, (void *)&ifr);
	if (ret < 0) {
		jlog(L_ERROR, "tun_ifreq]> ioctl TUNSETIFF :: %s:%i", __FILE__, __LINE__);
		return -1;
	}

	ret = ioctl(*fd, TUNGETIFF, (void *)&ifr);
	if (ret < 0) {
		jlog(L_ERROR, "tun_ifreq]> ioctl TUNGETIFF :: %s:%i", __FILE__, __LINE__);
		return -1;
	}

	snprintf(devname, IFNAMSIZ, "%s", ifr.ifr_name);
	jlog(L_DEBUG, "tun_ifreq: devname: %s %s", ifr.ifr_name, devname);

	return ret;
}
