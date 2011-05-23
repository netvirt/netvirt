#ifndef DNDS_SCHED_H
#define DNDS_SCHED_H

#include <time.h>

extern int scheduler_init();
extern void sched_register(int, char *, void (*)(void *), unsigned int, void *udata);
extern void scheduler();

typedef struct task {

	struct task *next;
	char *name;
	void (*cb)(void *);
	long frequency;
	time_t lastexec;
	void *udata;

} task_t;

enum {
	SCHED_APERIODIC = 0,
	SCHED_PERIODIC,
	SCHED_SPORADIC,
	SCHED_MAX /* This one MUST be the last */
};

#endif /* DNDS_SCHED_H */
