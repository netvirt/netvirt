// Copyright (C) Mind4Networks - Benjamin Vanheuverzwijn, 2010

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>
#include <sys/time.h>

#include "chronos.h"
#include "utils.h"
#include "xsched.h"
#include "journal.h"

/* FIXME
 * this subsystem have to be completely replaced by a garbage collector
 */

/*
 * Implementation details:
 *  I start a scheduled task (timer_process) in the scheduler that will handle the
 *  callbacks to call
 *  XXX - you must init the module after intiatiating the scheduler
 */

static timeout_t *first_timeout;
static timeout_t *last_timeout;
uint8_t *timeout_id_pool;
#define TIMEOUT_ID_POOL_SIZE 256

void chronos_init(void)
{
	first_timeout = last_timeout = NULL;

	alloc_bitmap(TIMEOUT_ID_POOL_SIZE, &timeout_id_pool);
}

/*
 * Init the chronos subsystem
 *
 * XXX - You must call this *after* initiating the scheduler
 */
void chronos_init_scheduler(void)
{
	chronos_init();
	sched_register(SCHED_APERIODIC, "chronos", &chronos_process_timeout, 0, NULL);
}

/*
 * Clean the chronos subsystem. Must be call before stoping chronos
 *
 * free() everything
 */
void chronos_fini()
{
	timeout_t *current = first_timeout;
	timeout_t *next = first_timeout->next;

	while(current != NULL) {
		free(current);
		current = next;
		next = current->next;
	}
}

/*
 * Add a timeout to the list
 *
 * @return a timer id
 */
int chronos_add(int interval, void (*callback)(void *), void *ext_ptr)
{
	int id;

	id = chronos_generate_id();
	if (id == -1) {
		JOURNAL_ERR("chronos]> creation of a new timer failed :: %s:%i\n", __FILE__, __LINE__);
		return -1;
	}

	timeout_t *timeout = calloc(1, sizeof(timeout_t));
	timeout->id = id;
	timeout->interval = interval;
	gettimeofday(&timeout->timeset, NULL);
	timeout->msec_remain;
	timeout->callback = callback;
	timeout->ext_ptr = ext_ptr;
	timeout->next = NULL;
	timeout->prev = NULL;

	if (first_timeout == NULL) {
		first_timeout = timeout;
		last_timeout = timeout;
	}
	else {
		// append the timeout on the list
		timeout->prev = last_timeout;
		last_timeout->next = timeout;
		last_timeout = timeout;
	}

	return timeout->id;
}

/*
 * Remove a timeout function
 *
 * @param timeout_id identifier of a timeout (provided by chronos_add)
 */
void chronos_remove(int timeout_id)
{
	timeout_t *timeout = chronos_find_timeout(timeout_id);

	// XXX this is broken

	if (timeout != NULL) {

		printf("found to remove\n");
		if (timeout->prev != NULL) {
			// we were not the first timeout
			timeout->prev->next = timeout->next;
		}

		if (timeout->next != NULL) {
			// we were not the last timeout
			timeout->next->prev = timeout->prev;
		}

		free_bit(timeout_id_pool, TIMEOUT_ID_POOL_SIZE, timeout_id);
		free(timeout);
	}
}

/*
 * Process the list of timeout. Should be call in a while(1) or frequently enough.
 */
void chronos_process_timeout()
{
	timeout_t *current = first_timeout;

	while (current != NULL ) {
		chronos_heartbeat(current);
		printf("tmout in %i\n", current->msec_remain);
		if (current->msec_remain <= 0) {
			// there we go
			current->callback(current->ext_ptr);
//			current->remaining = current->interval;
		}

		current = current->next;
	}
}

static int chronos_generate_id()
{
//	static unsigned int counter = 0;
//	return ++counter;

	int ret;
	uint32_t id = 0;
	ret = allocate_bit(timeout_id_pool, TIMEOUT_ID_POOL_SIZE, &id);
	if (ret == -1) // the pool has been exhausted
		return -1;

	return id;
}

/*
 * Find a timeout by its identifier
 * FIXME - O(n) search
 */
static timeout_t *chronos_find_timeout(int timeout_id)
{
	timeout_t *current = first_timeout;
	while (current != NULL) {
		if (current->id == timeout_id) {
			return current;
		}

		current = current->next;
	}

	return NULL;
}

/*
 * Change the remaining wait time of a task
 *
 * hearbeat tries to compensate for the lost executing time
 */
static void chronos_heartbeat(timeout_t *timeout)
{
	struct timeval now, time_offset;
	unsigned int msec_elapsed;

	if (timeout == NULL) {
		return;
	}

	gettimeofday(&now, NULL);

	time_offset.tv_sec = now.tv_sec - timeout->timeset.tv_sec;
	time_offset.tv_usec = now.tv_usec - timeout->timeset.tv_usec;

	msec_elapsed = (unsigned int)(time_offset.tv_sec * 1000) + (time_offset.tv_usec / 1000); // convert to msec

	timeout->msec_remain = timeout->interval - msec_elapsed;
	printf("msec %i\n", timeout->msec_remain);

	if (timeout->msec_remain <= 0)	// reset timer
		timeout->timeset = now;
}

/*
 * Main to test things and an example of implementation
 */
/*
void task1_callback(void *args);
void task2_callback(void *args);
void task3_callback(void *args);

int main(int argc, char *argv[]) {

    int task1_id;
    int task2_id;
    int task3_id;

    // Init the subsystem
    chronos_init();

    // Add two task
    task1_id = chronos_add(1000, task1_callback, NULL);
    task2_id = chronos_add(3000, task2_callback, NULL);
    task3_id = chronos_add(500, task3_callback, "hihihi");

    while (1) {
        chronos_process_timeout();
        usleep(100);
    }
}

void task1_callback(void *args) {
    printf("hello world from task1!\n");
}

void task2_callback(void *args) {
    printf("hello world from task2!\n");
}

void task3_callback(void *args) {
    char *string = (char *)args;
    printf("hello world from task3! param: <%s>\n", string);
}
*/
