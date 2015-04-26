#include "nvcm.pb-c.h"
#include <stdio.h>


test_AddRequest()
{
	NVCMsg msg = NVCMSG__INIT;
	AddRequest addRequest = ADD_REQUEST__INIT;
	Object object = OBJECT__INIT;
	Client client = CLIENT__INIT;

	msg.version = 1;
	msg.addrequest = &addRequest;
	msg.addrequest->object = &object;
	msg.addrequest->object->client = &client;


	printf("%d\n", msg.version);
}

int main()
{
	test_AddRequest();

	return 0;
}
