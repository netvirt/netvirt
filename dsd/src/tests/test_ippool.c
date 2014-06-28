#include <stdio.h>
#include "../ippool.h"

int main()
{
	char *ip = NULL;
	ippool_t *my_pool = NULL;

	my_pool = ippool_new("44.128.1.0", "255.255.255.0");

	if (my_pool == NULL)
		return -1;

	do {
		ip = ippool_get_ip(my_pool);
		if (ip)
			printf("ip: %s\n", ip);
	} while (ip);

	printf("the end!\n");

	return 0;
}
