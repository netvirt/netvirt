/*
 * ipf.c: IP Filter API
 *
 * Copyright (C) 2010 Nicolas Bouliane
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; version 2
 * of the License.
 *
 */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include "aclset.h"
#include "ipset.h"
#include "ipf.h"

#define IPF_ACCEPT	0x01	// FIXME use enum
#define	IPF_DENY	0x02

/* TODO
 * replace all printf() with journal
 */

typedef struct rule {

	ipset_t *ipset_src;
	ipset_t *ipset_dst;
	uint8_t verdict;

	struct rule *next;
	struct rule *prev;

} rule_t;

struct ipf {

	rule_t *rules;
	uint8_t default_policy;

};

ipf_t *ipf_new()
{
	ipf_t *ipf;

	ipf = calloc(1, sizeof(ipf_t));
	ipf->rules = NULL;
	ipf->default_policy = IPF_ACCEPT;

	return ipf;
}

void ipf_del(ipf_t *ipf)
{
	rule_t *rule;

	do {
		rule = ipf->rules;

		if (rule != NULL) {
			ipf->rules = ipf->rules->next;
			free(rule);
		}

	} while (ipf->rules != NULL);

	free(ipf);
}

int ipf_rule_append(ipf_t *ipf, ipset_t *ipset_src, ipset_t *ipset_dst, uint8_t verdict)
{
	rule_t *rule;
	rule = calloc(1, sizeof(rule_t));

	rule->ipset_src = ipset_src;
	rule->ipset_dst = ipset_dst;
	rule->verdict = verdict;

	rule->next = NULL;
	rule->prev = NULL;

	if (ipf->rules == NULL) {
		ipf->rules = rule;
		ipf->rules->prev = ipf->rules;

	} else {
		ipf->rules->prev->next = rule;
		rule->prev = ipf->rules->prev->next;
		ipf->rules->prev = rule;
	}

	return 0;
}

int ipf_rule_del(ipf_t *ipf, ipset_t *ipset_src, ipset_t *ipset_dst, uint8_t verdict)
{
	rule_t *rule;
	rule = ipf->rules;

	while (rule != NULL) {

		if (rule->ipset_src == ipset_src
			&& rule->ipset_dst == ipset_dst
			&& rule->verdict == verdict) {

			// we've found the node to remove
			break;
		}
		rule = rule->next;
	}

	if (rule == NULL) {
		printf("not found\n");
		return -1;
	}

	if (rule == ipf->rules)
		ipf->rules = rule->next;

	else {
		if (rule->prev != NULL)
			rule->prev->next = rule->next;

		if (rule->next != NULL)
			rule->next->prev = rule->prev;
	}

	free(rule);
	return 0;
}

void ipf_default_policy(ipf_t *ipf, uint8_t verdict)
{
	if (verdict == IPF_ACCEPT)
		ipf->default_policy = IPF_ACCEPT;

	else if (verdict == IPF_DENY)
		ipf->default_policy = IPF_DENY;

	else
		printf("ipf]> failed trying to set default policy\n");
}

uint8_t ipf_filter(ipf_t *ipf, const char *ip_src, const char *ip_dst)
{
	int ret;
	uint8_t verdict;

	rule_t *rule;
	rule = ipf->rules;

	verdict = ipf->default_policy;

	while (rule != NULL) {

		if (ipset_find(rule->ipset_src, ip_src) == 0
			&& ipset_find(rule->ipset_dst, ip_dst) == 0) {

			verdict = rule->verdict;
			break;
		}

		rule = rule->next;
	}

	return verdict;
}
/*
static void ipf_rule_show(ipf_t *ipf)
{
	rule_t *rule_itr;
	rule_itr = ipf->rules;

	while (rule_itr != NULL) {
		printf("%p\n", rule_itr);
		rule_itr = rule_itr->next;
	}
}

int main()
{
	aclset_t *aclset; // aclset contain multiple ipset
	aclset = aclset_new();

	ipset_t *ipset; // ipset contain multiple ip

	ipset = ipset_new();
	ipset_insert(ipset, "192.168.10.1");
	ipset_insert(ipset, "192.168.10.2");
	ipset_printset(ipset);
	aclset_insert(aclset, 1, ipset);
	ipset = NULL;

	ipset = ipset_new();
	ipset_insert(ipset, "192.168.10.11");
	ipset_insert(ipset, "192.168.10.12");
	ipset_printset(ipset);
	aclset_insert(aclset, 2, ipset);
	ipset = NULL;

	aclset_printset(aclset);

	ipf_t *ipf;
	ipf = ipf_new();

	ipset_t *ipset1, *ipset2;

	ipset1 = aclset_find(aclset, 1);
	ipset_printset(ipset1);

	ipset2 = aclset_find(aclset, 2);
	ipset_printset(ipset2);

	ipf_default_policy(ipf, IPF_DENY);
	uint8_t verdict;

	ipf_rule_append(ipf, ipset1, ipset2, IPF_ACCEPT);
	ipf_rule_append(ipf, ipset2, ipset1, IPF_ACCEPT);
	ipf_rule_append(ipf, ipset2, ipset2, IPF_ACCEPT);

	verdict = ipf_filter(ipf, "192.168.10.1", "192.168.10.11");
	printf("verdict %i\n", verdict);

	verdict = ipf_filter(ipf, "192.168.10.11", "192.168.10.2");
	printf("verdict %i\n", verdict);

	verdict = ipf_filter(ipf, "192.168.10.11", "192.168.10.12");
	printf("verdict %i\n", verdict);

	ipf_rule_show(ipf);

	ipf_rule_del(ipf, ipset1, ipset2, IPF_ACCEPT);
	ipf_rule_del(ipf, ipset2, ipset1, IPF_ACCEPT);
	ipf_rule_del(ipf, ipset2, ipset2, IPF_ACCEPT);

	verdict = ipf_filter(ipf, "192.168.10.1", "192.168.10.11");
	printf("verdict %i\n", verdict);

	verdict = ipf_filter(ipf, "192.168.10.11", "192.168.10.2");
	printf("verdict %i\n", verdict);

	verdict = ipf_filter(ipf, "192.168.10.11", "192.168.10.12");
	printf("verdict %i\n", verdict);

	ipf_rule_show(ipf);

	ipf_del(ipf);
}
*/
