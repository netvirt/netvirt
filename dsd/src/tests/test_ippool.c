#include <stdio.h>
#include <string.h>

#include "../ippool.h"

int main()
{
	char *lip, *ip = NULL;
	struct ippool *my_pool = NULL;

	my_pool = ippool_new("0.0.0.0", "257.0.0.0");
	if (my_pool != NULL) {
		printf("%d\n", __LINE__);
		return -1;
	}

	my_pool = ippool_new("0.0.0.257", "255.255.255.0");
	if (my_pool != NULL) {
		printf("%d\n", __LINE__);
		return -1;
	}

	my_pool = ippool_new("44.128.1.0", "255.255.255.0");

	if (my_pool == NULL) {
		printf("%d\n", __LINE__);
		return -1;
	}

	ip = ippool_get_ip(my_pool);
	if (ip == NULL) {
		printf("%d\n", __LINE__);
		return -1;
	}

	/* Check the first ip address of the pool. */
	if (strcmp(ip, "44.128.1.1") != 0) {
		printf("%d\n", __LINE__);
		return -1;
	}

	do {
		lip = ip;
		ip = ippool_get_ip(my_pool);
	} while (ip);

	/* Check the last ip address of the pool. */
	if (strcmp(lip, "44.128.1.254") != 0) {
		printf("%d\n", __LINE__);
		return -1;
	}

	ippool_release_ip(my_pool, "44.128.1.10");
	ip = ippool_get_ip(my_pool);
	if (strcmp(ip, "44.128.1.10") != 0) {
		printf("%d\n", __LINE__);
		return -1;
	}

	ippool_release_ip(my_pool, "44.128.1.0");
	ip = ippool_get_ip(my_pool);
	/* 'ip' must be NULL. */
	if (ip != NULL) {
		printf("%d\n", __LINE__);
		return -1;
	}

	ippool_release_ip(my_pool, "44.128.1.254");
	ip = ippool_get_ip(my_pool);
	if (strcmp(ip, "44.128.1.254") != 0) {
		printf("%d\n", __LINE__);
		return -1;
	}

	/* Try a non-valid address. */
	ippool_release_ip(my_pool, "44.128.1.256");
	ip = ippool_get_ip(my_pool);
	/* 'ip' must be NULL. */
	if (ip != NULL) {
		printf("%d\n", __LINE__);
		return -1;
	}

	ippool_free(my_pool);

	return 0;
}
