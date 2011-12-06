// Directory Service Request
// Copyright (C) Nicolas Bouliane, Mind4Networks, 2010

#ifndef REQUEST_H
#define REQUEST_H

#include <dnds/dnds.h>
#include "dsd.h"

void authRequest(ds_sess_t *sess, DNDSMessage_t *msg);
void addRequest(ds_sess_t *sess, DNDSMessage_t *msg);
void delRequest(ds_sess_t *sess, DNDSMessage_t *msg);
void modifyRequest(ds_sess_t *sess, DNDSMessage_t *msg);
void searchRequest(ds_sess_t *sess, DNDSMessage_t *msg);

#endif // REQUEST_H

