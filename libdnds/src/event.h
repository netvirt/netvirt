#ifndef DNDS_EVENT_H
#define DNDS_EVENT_H

int event_init();
int event_register(int, char *, void (*)(void *), int);
void event_throw(int, void *);

#define PRIO_HIGH 0X01
#define PRIO_LOW 0X02
#define PRIO_AGNOSTIC 0X04

typedef struct event {

    struct event *next;
    char *name;
    void (*cb)(void *);
    int prio;

} event_t;

enum {
	EVENT_EXIT = 0,
	EVENT_SCHED,
	EVENT_MAX /* This one MUST be the last */
};

#endif /* DNDS_EVENT_H */
