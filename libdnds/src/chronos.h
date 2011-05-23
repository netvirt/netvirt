/*
 * See COPYRIGHT file
 */

#ifndef _XIA_CHRONOS_H
#define _XIA_CHRONOS_H

typedef struct timeout {

	int id;

	unsigned int interval; // interval of exec, millisecond
	int msec_remain; // remaining time before execute, millisecond
	struct timeval timeset;

	void (*callback)(void *);
	void *ext_ptr;

	struct timeout *next;
	struct timeout *prev;

} timeout_t;

/*
 * Init the chronos subsystem
 *
 * XXX - You must call this *after* initiating the scheduler
 */
void chronos_init();

/*
 * Clean the chronos subsystem. Must be call before stoping chronos
 *
 * free() everything
 */
void chronos_fini();

/*
 * Add a function to be called every 'interval`
 *
 * @return timer id
 */
int chronos_add(int interval, void (*callback)(void *), void *cb_argv);

/*
 * Remove a timeout function
 *
 * @param timer_id identifier of a timeout (provided by chronos_add)
 */
void chronos_remove(int timeout_id);

/*
 * Process the list of timeout. Should be call in a while(1) or frequently enough.
 */
void chronos_process_timeout();

/*
 * Generate a timeout identifier
 */
static int chronos_generate_id();

/*
 * Find a timeout by its identifier
 */
static timeout_t *chronos_find_timeout(int timeout_id);

/*
 * Update the remaining time on a timeout
 *
 * hearbeat tries to compensate for the lost executing time
 */
static void chronos_heartbeat(timeout_t *timeout);

#endif
