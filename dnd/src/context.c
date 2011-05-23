/*
 * context.c: Context API
 *
 * Copyright (C) 2010 Nicolas Bouliane
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

#include <dnds/event.h>
#include <dnds/hash.h>
#include <dnds/journal.h>
#include <dnds/netbus.h>
#include <dnds/pki.h>
#include <dnds/inet.h>

#include "context.h"
#include "session.h"

#define CONTEXT_LIST_SIZE 256
context_t *context_table[CONTEXT_LIST_SIZE] = {NULL};

void context_del_session(context_t *context, session_t *session)
{
	if (session == context->session_list)
		context->session_list = NULL;

	else {
		if (session->prev)
			session->prev->next = session->next;
		else
			printf("no previons link ??!\n");
	}
}

void context_add_session(context_t *context, session_t *session)
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
}

context_t *context_lookup(uint32_t context_id)
{
	if (context_id >= 0 && context_id < CONTEXT_LIST_SIZE)
		return context_table[context_id];

	return NULL;
}

int context_create(uint32_t id, char *address, char *netmask )
{
	context_t *context;

	context = (context_t*)malloc(sizeof(context_t));
	context_table[id] = context;

	JOURNAL_DEBUG("context]> id	:: %i", id);
	JOURNAL_DEBUG("context]> subnet :: %s", address);
	JOURNAL_DEBUG("context]> netmask:: %s", netmask);

	context->ippool = ippool_new(address, netmask);
	context->id = id;

	// no port yet
	context->session_list = NULL;

	context->ftable = ftable_new(1024, session_itemdup, session_itemrel);
	return 0;
}

void context_fini(void *ext_ptr)
{
	int i = 0;
	context_t *context;

	while (context_table[i] != NULL) {
		context = context_table[i];
		i++;
	}
}

int context_init()
{
	int ret;

	event_register(EVENT_EXIT, "context:context_fini()", context_fini, PRIO_AGNOSTIC);
	context_create(1, "192.168.10.0", "255.255.255.0");

	return 0;
}
