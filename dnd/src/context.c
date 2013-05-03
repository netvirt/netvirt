/*
 * Dynamic Network Directory Service
 * Copyright (C) 2009-2013
 * Nicolas J. Bouliane <nib@dynvpn.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; version 2
 * of the License.
 *
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <bitv.h>
#include <logger.h>
#include <crypto.h>
#include <netbus.h>
#include <inet.h>

#include "context.h"
#include "hash.h"
#include "session.h"

/* XXX the context list should be a tree, or a hashlist */

#define CONTEXT_LIST_SIZE 512
context_t *context_table[CONTEXT_LIST_SIZE] = {NULL};

void context_del_session(context_t *context, struct session *session)
{
	if (session->next == NULL) {
		if (session->prev == NULL)
			context->session_list = NULL;
		else
			session->prev->next = NULL;
	} else {
		if (session->prev == NULL) {
			context->session_list = session->next;
			session->next->prev = NULL;
		}
		else {
			session->prev->next = session->next;
			session->next->prev = session->prev;
		}
	}

	bitpool_release_bit(context->bitpool, 1024, session->id);
}

void context_add_session(context_t *context, struct session *session)
{
	if (context->session_list == NULL) {
		context->session_list = session;
		context->session_list->next = NULL;
		context->session_list->prev = NULL;
	}
	else {
		session->next = context->session_list;
		context->session_list->prev = session;
		context->session_list = session;
	}

	bitpool_allocate_bit(context->bitpool, 1024, &session->id);
}

void context_show_session_list(context_t *context)
{
	struct session *itr = NULL;
	itr = context->session_list;

	while (itr != NULL) {
		jlog(L_DEBUG, "session: %p:%s\n", itr, itr->ip);
		itr = itr->next;
	}
	jlog(L_DEBUG, "--\n");
}


context_t *context_lookup(uint32_t context_id)
{
	jlog(L_NOTICE, "lookup id %d\n", context_id);
	if (context_id < CONTEXT_LIST_SIZE)
		return context_table[context_id];

	return NULL;
}

int context_create(uint32_t id, char *address, char *netmask,
			char *serverCert, char *serverPrivkey, char *trustedCert)
{
	context_t *context;

	context = (context_t*)malloc(sizeof(context_t));
	context_table[id] = context;

	jlog(L_DEBUG, "context]> id	:: %i", id);
	jlog(L_DEBUG, "context]> subnet :: %s", address);
	jlog(L_DEBUG, "context]> netmask:: %s", netmask);

	context->id = id;

	context->passport = pki_passport_load_from_memory(serverCert, serverPrivkey, trustedCert);

	bitpool_new(&context->bitpool, 1024);
	context->linkst = linkst_new(1024);

	context->session_list = NULL;

	context->ftable = ftable_new(1024, session_itemdup, session_itemrel);
	return 0;
}

int context_init()
{
	return 0;
}
