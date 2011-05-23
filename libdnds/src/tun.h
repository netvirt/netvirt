#ifndef DNDS_TUN_H
#define DNDS_TUN_H

#include "netbus.h"

typedef struct tun {

	char devname[16];
	int fd;

	void (*on_input)();

	int (*write)(struct iface *, void *, int);
	int (*read)(struct iface *);
	void (*shutdown)();

	void *frame;
	void *ext_ptr;

} tun_t;

int tun_up(char *, char *);
int tun_create(char *, int *);
int tun_destroy(iface_t *);

#endif // DNDS_TUN_H
