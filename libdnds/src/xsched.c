/*
 * xsched.c: Task scheduler API
 *
 * Copyright (C) 2010 Nicolas Bouliane
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; version 2
 * of the License.
 *
 */

#include <signal.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/time.h>
#include <unistd.h>

#include "event.h"
#include "journal.h"
#include "xsched.h"
#include "utils.h"

static task_t *tasks[SCHED_MAX] = {NULL};
static task_t *p_aperiodic = NULL;

static volatile int periodic_ready = false;
static volatile int periodic_sched = false;
static int sched_running = false;

void insort_periodic_task(task_t *tsk)
{
	task_t *itr;
	itr = tasks[SCHED_PERIODIC];

	if (itr == NULL) {
		tasks[SCHED_PERIODIC] = tsk;
		return;
	}

	if (abs(tsk->frequency - tsk->lastexec) < abs(itr->frequency - itr->lastexec)) {
		tsk->next = itr;
		tasks[SCHED_PERIODIC] = tsk;
	}
	else {
		for (itr = tasks[SCHED_PERIODIC]; itr != NULL; itr = itr->next) {
			if (itr->next == NULL) {
				itr->next = tsk;
				tsk->next = NULL;
			}
			else if (abs(tsk->frequency - tsk->lastexec)
				    < abs(itr->next->frequency - itr->next->lastexec)) {

				tsk->next = itr->next;
				itr->next = tsk;
			}
		}
	}
}

void sort_periodic_tasks()
{
	task_t *tsk;
	tsk = tasks[SCHED_PERIODIC];

	tasks[SCHED_PERIODIC] = tsk->next;
	insort_periodic_task(tsk);
}

extern void sched_register(int rhythm, char *name, void (*cb)(void *), unsigned int param, void *udata)
{
	task_t *tsk = malloc(sizeof(task_t));
	tsk->name = strdup(name);
	tsk->cb = cb;
	tsk->frequency = param;
	tsk->lastexec = 0;
	tsk->udata = udata;

	if (tasks[rhythm] == NULL) {

		tasks[rhythm] = tsk;
		tsk->next = NULL;

	} else {

		if (rhythm == SCHED_PERIODIC) {
			insort_periodic_task(tsk);
		}

		else if (rhythm == SCHED_APERIODIC) {
			tsk->next = tasks[rhythm];
			tasks[rhythm] = tsk;
		}
		else if (rhythm == SCHED_SPORADIC) {
			tsk->next = tasks[rhythm];
			tasks[rhythm] = tsk;
		}
	}
}

task_t *get_next_task()
{
	task_t *tsk;
	struct itimerval it;
	memset(&it, 0, sizeof(struct itimerval));

	/* identify the best candidate among all tasks */
	if (tasks[SCHED_PERIODIC] != NULL && periodic_ready) {

		tsk = tasks[SCHED_PERIODIC];
		tsk->lastexec = time(NULL);
		periodic_ready = false;

	}
	else if (tasks[SCHED_APERIODIC] != NULL) {

		if (p_aperiodic == NULL || p_aperiodic->next == NULL)
			p_aperiodic = tasks[SCHED_APERIODIC];
		else
			p_aperiodic = p_aperiodic->next;

		tsk = p_aperiodic;
	}
	else
		tsk = NULL;

	if (tasks[SCHED_PERIODIC] != NULL && !periodic_sched) {

		/* recompute tasks' lists */
		sort_periodic_tasks();

		/* set the timer for the next task */
		it.it_value.tv_sec = tasks[SCHED_PERIODIC]->frequency;
		setitimer(ITIMER_REAL, &it, NULL);

		periodic_sched = true;
	}

	return tsk;
}

void do_event_sched(void *context)
{
	periodic_ready = true;
	periodic_sched = false;
}

void sched_stop()
{
	sched_running = false;
}

int scheduler_init()
{
	event_register(EVENT_SCHED, "scheduler::do_event_sched()", do_event_sched, PRIO_HIGH);
	event_register(EVENT_EXIT, "scheduler::sched_stop()", sched_stop, PRIO_LOW);

	return 0;
}

void scheduler()
{
	task_t *tsk;
	int ret;

	sigset_t block_mask, old_mask;
	sigfillset(&block_mask);

	sched_running = true;

	do {
		sigprocmask(SIG_BLOCK, &block_mask, &old_mask);
		// XXX sigprocmask() can fail. so what ?

		tsk = get_next_task();
//		JOURNAL_NOTICE("task]> %s", tsk->name);

		if (tsk != NULL	)
			tsk->cb(tsk->udata);

		ret = sigprocmask(SIG_SETMASK, &old_mask, NULL);
//		printf("sched sigprocmask : %i\n", 1);
///		sleep(1);

	} while (sched_running);

	JOURNAL_NOTICE("sched]> i'm off.");
}
