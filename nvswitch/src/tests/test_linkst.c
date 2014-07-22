#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include "../linkst.h"

int main()
{
	int ret = 0;

        linkst_t *linkst = NULL;

        /* there is 4 active node */
        int idx_a, idx_b, idx_c, idx_d;

        idx_a = 1;
        idx_b = 2;
        idx_c = 3;
        idx_d = 100;

        linkst = linkst_new(100, 3);

	/* test invalid linkst */
	ret = linkst_join(NULL, 1, 2);
	if (ret != -1) {
		goto out;
	}

        ret = linkst_join(linkst, idx_a, idx_b);
	if (ret == -1) {
		goto out;
	}

	/* test invalid linkst */
	ret = linkst_joined(NULL, 1, 2);
	if (ret == 1) {
		goto out;
	}

        ret = linkst_joined(linkst, idx_a, idx_b);
	if (ret != 1) {
		goto out;
        }

        ret = linkst_join(linkst, idx_a, idx_d);
	if (ret == -1) {
		goto out;
	}

        ret = linkst_joined(linkst, idx_a, idx_d);
	if (ret != 1) {
		goto out;
        }

	/* timeout the link after 3 sec */
	sleep(4);

	ret = linkst_joined(linkst, idx_a, idx_b);
	if (ret == 1) {
		goto out;
	}

	ret = linkst_joined(linkst, idx_a, idx_c);
	if (ret == 1) {
		goto out;
	}

	/* relink them */
        ret = linkst_join(linkst, idx_a, idx_b);
	if (ret == -1) {
		goto out;
	}

        ret = linkst_join(linkst, idx_a, idx_d);
	if (ret == -1) {
		goto out;
	}

	/* test invalid linkst */
	ret = linkst_disjoin(NULL, 1);
	if (ret != -1) {
		goto out;
	}

        ret = linkst_disjoin(linkst, idx_a);
	if (ret == -1) {
		goto out;
	}

        ret = linkst_joined(linkst, idx_a, idx_b);
	if (ret == 1) {
		goto out;
	}

        ret = linkst_joined(linkst, idx_a, idx_c);
	if (ret == 1) {
		goto out;
	}

	/* test invalid linkst */
	linkst_free(NULL);

        linkst_free(linkst);
	return 0;

out:
        linkst_free(linkst);
	return -1;
}

