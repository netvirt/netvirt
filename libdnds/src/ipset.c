/*
 * ipset.c: IP Set API
 *
 * Copyright (C) 2010 Nicolas Bouliane
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; version 2
 * of the License.
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>

#include "jsw_rbtree.h"
#include "ipset.h"

/* TODO
 * replace all printf() with journal
 */

static int ipset_cmp(const void *p1, const void *p2)
{
	return memcmp(p1, p2, sizeof(struct in_addr));
}

static void *ipset_dup(void *p)
{
	void *dup_p;

	dup_p = calloc(1, sizeof(struct in_addr));
	memmove(dup_p, p, sizeof(struct in_addr));

	return dup_p;
}

static void ipset_rel(void *p)
{
	free(p);
}

ipset_t *ipset_new()
{
	jsw_rbtree_t *rbtree;
	rbtree = jsw_rbnew(ipset_cmp, ipset_dup, ipset_rel);

	return rbtree;
}

void ipset_delete(ipset_t *ipset)
{
	jsw_rbdelete(ipset);
}

int ipset_insert(ipset_t *ipset, const char *ip)
{
	int ret;
	struct in_addr *in;

	in = calloc(1, sizeof(struct in_addr));
	ret = inet_pton(AF_INET, ip, in);

	if (ret != 1) {
		printf("ipset]> insert invalid ip %s\n", ip);
		free(in);
		return -1;
	}

	ret = jsw_rbinsert(ipset, (void*)in);
	if (ret == 0) {
		printf("ipset]> insert failed on ip %s\n", ip);
		free(in);
		return -1;
	}

	return 0;
}

int ipset_erase(ipset_t *ipset, const char *ip)
{
	int ret;
	struct in_addr *in;

	in = calloc(1, sizeof(struct in_addr));
	ret = inet_pton(AF_INET, ip, in);

	if (ret != 1) {
		printf("ipset]> delete invalid ip %s\n", ip);
		free(in);
		return -1;
	}

	ret = jsw_rberase(ipset, (void*)in);
	if (ret == 0) {
		printf("ipset]> erase failed on ip %s\n", ip);
		free(in);
		return -1;
	}

	return 0;
}

int ipset_find(ipset_t *ipset, const char *ip)
{
	int ret;
	struct in_addr *in;
	in = calloc(1, sizeof(struct in_addr));
	ret = inet_pton(AF_INET, ip, in);

	if (ret != 1) {
		printf("ipset]> find invalid ip\n");
		free(in);
		return -1;
	}

	if (jsw_rbfind(ipset, in) == NULL)
		return -1;

	return 0;
}

void ipset_printset(ipset_t *ipset)
{
	struct in_addr *iptrav;

	jsw_rbtrav_t *rbtrav;
	rbtrav = jsw_rbtnew();

	iptrav = jsw_rbtfirst(rbtrav, ipset);
	printf("ip %s\n", inet_ntoa(*iptrav));

	while ((iptrav = jsw_rbtnext(rbtrav)) != NULL) {
		printf("ip %s\n", inet_ntoa(*iptrav));
	}
}

/*

int main()
{
	ipset_t *ipset;
	ipset = ipset_new();

	ipset_insert(ipset, "192.168.0.19");
	ipset_insert(ipset, "192.168.0.2");
	ipset_insert(ipset, "192.168.0.8");
	ipset_insert(ipset, "192.168.0.15");
	ipset_insert(ipset, "192.168.0.0");

	int ret;

	ret = ipset_find(ipset, "192.168.0.11");
	printf("find .11? %i\n", ret);

	ret = ipset_find(ipset, "192.168.0.8");
	printf("find .8? %i\n", ret);

	ret = ipset_find(ipset, "192.168.0.000");
	printf("find ? %i\n", ret);

	ret = ipset_erase(ipset, "192.168.0.8");
	printf("erase %i\n", ret);

	ret = ipset_find(ipset, "192.168.0.8");
	printf("find .8? %i\n", ret);

	ipset_printset(ipset);

	ipset_delete(ipset);
}
*/
