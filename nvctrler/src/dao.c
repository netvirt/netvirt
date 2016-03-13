/*
 * NetVirt - Network Virtualization Platform
 * Copyright (C) 2009-2016
 * Nicolas J. Bouliane <admin@netvirt.org>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation; version 3 of the license.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details
 */

/* gcc dao.c -lpq -lnvcore -lossp-uuid
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <postgresql/libpq-fe.h>
#include <ossp/uuid.h>

#include <logger.h>

#include "ctrler.h"
#include "pki.h"

PGconn *dbconn = NULL;

char *uuid_v4(void)
{
	uuid_t *uuid = NULL;
	char *str = NULL;

	uuid_create(&uuid);
	uuid_make(uuid, UUID_MAKE_V4);

	uuid_export(uuid, UUID_FMT_STR, &str, NULL);
	uuid_destroy(uuid);

	return str;
}

int check_result_status(PGresult *result)
{
	switch (PQresultStatus(result)) {
	case PGRES_COMMAND_OK:
		jlog(L_DEBUG, "command executed ok, %s rows affected", PQcmdTuples(result));
		break;

	case PGRES_TUPLES_OK:
		jlog(L_DEBUG, "query may have returned data");
		break;

	default:
		jlog(L_WARNING, "command failed with code %s, error message %s",
			PQresStatus(PQresultStatus(result)),
			PQresultErrorMessage(result));

		return -1;
	}

	return 0;
}

/*
create or replace function inet_mask(inet,inet) returns inet language sql
immutable as $f$ select set_masklen($1,i)
from generate_series(0, case when family($2)=4 then 32 else 128 end) i
where netmask(set_masklen($1::cidr, i)) = $2; $f$;
*/

int dao_prepare_statements()
{
	PGresult *result = NULL;

	result = PQprepare(dbconn,
			"dao_add_client",
			"INSERT INTO client "
			"(email, password, apikey) "
			"VALUES ($1, crypt($2, gen_salt('bf')), $3);",
			0,
			NULL);

	check_result_status(result);
	if (result == NULL)
		goto error;
	PQclear(result);

	result = PQprepare(dbconn,
			"dao_activate_client",
			"UPDATE client "
			"SET status = 1 "
			"WHERE email = $1 "
			"AND apikey = $2;",
			0,
			NULL);
	check_result_status(result);
	if (result == NULL)
		goto error;
	PQclear(result);

	result = PQprepare(dbconn,
			"dao_update_client_apikey",
			"UPDATE client "
			"set apikey = $3 "
			"WHERE email = $1 "
			"AND apikey = $2;",
			0,
			NULL);
	check_result_status(result);
	if (result == NULL)
		goto error;
	PQclear(result);

	result = PQprepare(dbconn,
			"dao_fetch_account_apikey",
			"SELECT apikey "
			"FROM CLIENT "
			"WHERE email = $1 "
			"AND password = crypt($2, password) "
			"AND status = 1;",
			0,
			NULL);

	check_result_status(result);
	if (result == NULL)
		goto error;
	PQclear(result);

	result = PQprepare(dbconn,
			"dao_fetch_client_id_by_apikey",
			"SELECT id "
			"FROM CLIENT "
			"WHERE apikey = $1 "
			"AND status = 1;",
			0,
			NULL);

	check_result_status(result);
	if (result == NULL)
		goto error;
	PQclear(result);

	result = PQprepare(dbconn,
			"dao_fetch_client_id",
			"SELECT id "
			"FROM CLIENT "
			"WHERE email = $1 "
			"AND password = crypt($2, password);",
			0,
			NULL);

	check_result_status(result);
	if (result == NULL)
		goto error;
	PQclear(result);

	result = PQprepare(dbconn,
			"dao_del_context",
			"DELETE FROM context "
			"WHERE client_id = $1 "
			"AND id = $2;",
			0,
			NULL);

	check_result_status(result);
	if (result == NULL)
		goto error;
	PQclear(result);

	result = PQprepare(dbconn,
			"dao_add_context",
			"INSERT INTO CONTEXT "
			"(client_id, description, network, "
				"embassy_certificate, embassy_privatekey, embassy_serial, "
				"passport_certificate, passport_privatekey, ippool)"
			"VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9::bytea);",
			0,
			NULL);

	check_result_status(result);
	if (result == NULL)
		goto error;
	PQclear(result);

	result = PQprepare(dbconn,
			"dao_fetch_context_ippool",
			"SELECT ippool "
			"FROM CONTEXT "
			"WHERE id = $1;",
			0,
			NULL);

	check_result_status(result);
	if (result == NULL)
		goto error;
	PQclear(result);

	result = PQprepare(dbconn,
			"dao_fetch_network_id",
			"SELECT id "
			"FROM CONTEXT "
			"WHERE client_id = $1 "
			"AND description = $2;",
			0,
			NULL);

	check_result_status(result);
	if (result == NULL)
		goto error;
	PQclear(result);

	result = PQprepare(dbconn,
			"dao_fetch_context_embassy",
			"SELECT embassy_certificate, embassy_privatekey, embassy_serial, ippool "
			"FROM CONTEXT "
			"WHERE id = $1;",
			0,
			NULL);

	check_result_status(result);
	if (result == NULL)
		goto error;
	PQclear(result);

	result = PQprepare(dbconn,
			"dao_del_node",
			"DELETE FROM node "
			"WHERE context_id = $1 AND uuid = $2;",
			0,
			NULL);

	check_result_status(result);
	if (result == NULL)
		goto error;
	PQclear(result);

	result = PQprepare(dbconn,
			"dao_del_node_by_context_id",
			"DELETE FROM node "
			"WHERE context_id = $1",
			0,
			NULL);

	check_result_status(result);
	if (result == NULL)
		goto error;
	PQclear(result);

	result = PQprepare(dbconn,
			"dao_add_node",
			"INSERT INTO NODE "
			"(context_id, uuid, certificate, privatekey, provcode, description, ipaddress) "
			"VALUES ($1, $2, $3, $4, $5, $6, $7);",
			0,
			NULL);

	check_result_status(result);
	if (result == NULL)
		goto error;
	PQclear(result);

	result = PQprepare(dbconn,
			"dao_update_node_status",
			"UPDATE node "
			"SET status = $3, ipsrc = $4 "
			"WHERE context_id = $1 AND uuid = $2;",
			0,
			NULL);

	check_result_status(result);
	if (result == NULL)
		goto error;
	PQclear(result);

	result = PQprepare(dbconn,
			"dao_update_context_ippool",
			"UPDATE context "
			"SET ippool = $2::bytea "
			"WHERE Id = $1;",
			0,
			NULL);

	check_result_status(result);
	if (result == NULL)
		goto error;
	PQclear(result);

	result = PQprepare(dbconn,
			"dao_update_embassy_serial",
			"UPDATE context "
			"SET embassy_serial = $2 "
			"WHERE id = $1;",
			0,
			NULL);

	check_result_status(result);
	if (result == NULL)
		goto error;
	PQclear(result);

	result = PQprepare(dbconn,
			"dao_fetch_networks_by_client_id",
			"SELECT description "
			"FROM context "
			"WHERE client_id = $1;",
			0,
			NULL);

	check_result_status(result);
	if (result == NULL)
		goto error;
	PQclear(result);

	result = PQprepare(dbconn,
			"dao_fetch_network_by_client_id_desc",
			"SELECT id, description, client_id, host(network), netmask(network), passport_certificate, passport_privatekey, embassy_certificate "
			"FROM context "
			"WHERE client_id = $1 and description = $2;",
			0,
			NULL);

	check_result_status(result);
	if (result == NULL)
		goto error;
	PQclear(result);

	result = PQprepare(dbconn,
			"dao_fetch_context",
			"SELECT id, description, client_id, host(network), netmask(network), passport_certificate, passport_privatekey, embassy_certificate "
			"FROM context;",
			0,
			NULL);

	check_result_status(result);
	if (result == NULL)
		goto error;
	PQclear(result);

	result = PQprepare(dbconn,
			"dao_fetch_node_uuid_netid",
			"SELECT context_id, uuid "
			"FROM node",
			0,
			NULL);

	check_result_status(result);
	if (result == NULL)
		goto error;
	PQclear(result);

	result = PQprepare(dbconn,
			"dao_fetch_node_ip",
			"SELECT ipaddress "
			"FROM node "
			"WHERE context_id = $1 "
			"AND uuid = $2;",
			0,
			NULL);

	check_result_status(result);
	if (result == NULL)
		goto error;
	PQclear(result);

	result = PQprepare(dbconn,
			"dao_fetch_node_from_context_id",
			"SELECT uuid, description, provcode, ipaddress, status "
			"FROM node "
			"WHERE context_id = $1;",
			0,
			NULL);

	check_result_status(result);
	if (result == NULL)
		goto error;
	PQclear(result);

	return 0;

error:
	jlog(L_WARNING, "PQprepare error: %s", PQerrorMessage(dbconn));
	return -1;
}

void dao_disconnect()
{
	PQfinish(dbconn);
	dbconn = NULL;
}

int dao_connect(struct ctrler_cfg *ctrler_cfg)
{
	char conn_str[128];
	snprintf(conn_str, sizeof(conn_str), "dbname = %s user = %s password = %s host = %s",
						ctrler_cfg->db_name, ctrler_cfg->db_user, ctrler_cfg->db_pwd, ctrler_cfg->db_host);

	dbconn = PQconnectdb(conn_str);

	if (PQstatus(dbconn) != CONNECTION_OK) {
		jlog(L_ERROR, "Connection to database failed: %s", PQerrorMessage(dbconn));
		PQfinish(dbconn);
		return -1;
	} else {
		jlog(L_NOTICE, "DAO connected");
	}

	dao_prepare_statements();

	return 0;
}

void dao_dump_statements()
{
	PGresult *result;

        int nFields;
        int i, j;

	char *req = "select * from pg_prepared_statements;";

	result = PQexec(dbconn, req);
	if (!result) {
		jlog(L_WARNING, "PQexec command failed: %s", PQerrorMessage(dbconn));
	}

	if (check_result_status(result) == -1) {
		PQclear(result);
		return;
	}

        /* print out the attribute names */
        nFields = PQnfields(result);
        for (i = 0; i < nFields; i++)
                printf("%-15s", PQfname(result, i));
        printf("\n\n");

        /* print out the rows */
        for (i = 0; i < PQntuples(result); i++) {
                for (j = 0; j < nFields; j++)
                        printf("%-15s\n", PQgetvalue(result, i, j));
                printf("\n");
        }
	printf("\n\n");
	PQclear(result);
}

int dao_update_node_status(char *context_id, char *uuid, char *status, char *ipsrc)
{
	jlog(L_DEBUG, "context: %s", context_id);
	jlog(L_DEBUG, "uuid: %s", uuid);
	jlog(L_DEBUG, "status: %s", status);
	jlog(L_DEBUG, "ip src: %s", ipsrc);

	const char *paramValues[4];
	int paramLengths[4];
	PGresult *result = NULL;

	if (!context_id || !uuid || !status || !ipsrc) {
		jlog(L_WARNING, "invalid parameter");
		return -1;
	}

	paramValues[0] = context_id;
	paramValues[1] = uuid;
	paramValues[2] = status;
	paramValues[3] = ipsrc;

	paramLengths[0] = strlen(context_id);
	paramLengths[1] = strlen(uuid);
	paramLengths[2] = strlen(status);
	paramLengths[3] = strlen(ipsrc);

	result = PQexecPrepared(dbconn, "dao_update_node_status", 4, paramValues, paramLengths, NULL, 1);

	if (!result) {
		jlog(L_WARNING, "PQexec command failed: %s", PQerrorMessage(dbconn));
		return -1;
	}

	if (check_result_status(result) == -1) {
		PQclear(result);
		return -1;
	}

	PQclear(result);

	return 0;
}
int dao_update_client_apikey(char *email, char *apikey, char *new_apikey)
{
	const char *paramValues[3];
	int paramLengths[3];
	PGresult *result = NULL;

	if (!email || !apikey || !new_apikey) {
		jlog(L_WARNING, "invalid NULL parameter");
		return -1;
	}

	paramValues[0] = email;
	paramValues[1] = apikey;
	paramValues[2] = new_apikey;

	paramLengths[0] = strlen(email);
	paramLengths[1] = strlen(apikey);
	paramLengths[2] = strlen(new_apikey);

	result = PQexecPrepared(dbconn, "dao_update_client_apikey", 3, paramValues, paramLengths, NULL, 1);
	if (!result) {
		jlog(L_WARNING, "PQexec command failed: %s", PQerrorMessage(dbconn));
		return -1;
	}

	if (check_result_status(result) == -1) {
		PQclear(result);
		return -1;
	}

	PQclear(result);

	return 0;
}

int dao_activate_client(char *email, char *apikey)
{
	const char *paramValues[2];
	int paramLengths[2];
	PGresult *result = NULL;

	if (!email || !apikey) {
		jlog(L_WARNING, "invalid NULL parameter");
		return -1;
	}

	paramValues[0] = email;
	paramValues[1] = apikey;

	paramLengths[0] = strlen(email);
	paramLengths[1] = strlen(apikey);

	result = PQexecPrepared(dbconn, "dao_activate_client", 2, paramValues, paramLengths, NULL, 1);

	if (!result) {
		jlog(L_WARNING, "PQexec command failed: %s", PQerrorMessage(dbconn));
		return -1;
	}

	if (check_result_status(result) == -1) {
		PQclear(result);
		return -1;
	}

	PQclear(result);

	return 0;
}

int dao_add_client(char *email, char *password, char *apikey)
{

	const char *paramValues[3];
	int paramLengths[3];
	PGresult *result = NULL;

	if (!email || !password || !apikey) {

		jlog(L_WARNING, "invalid NULL parameter");
		return -1;
	}

	paramValues[0] = email;
	paramValues[1] = password;
	paramValues[2] = apikey;

	paramLengths[0] = strlen(email);
	paramLengths[1] = strlen(password);
	paramLengths[2] = strlen(apikey);

	result = PQexecPrepared(dbconn, "dao_add_client", 3, paramValues, paramLengths, NULL, 1);

	if (!result) {
		jlog(L_WARNING, "PQexec command failed: %s", PQerrorMessage(dbconn));
		return -1;
	}

	if (check_result_status(result) == -1) {
		PQclear(result);
		return -1;
	}

	PQclear(result);

	return 0;
}

int dao_fetch_account_apikey(char **apikey, char *email, char *password)
{

	const char *paramValues[2];
	int paramLengths[2];
	int tuples;
	int fields;
	PGresult *result = NULL;

	if (!apikey || !email || !password) {
		jlog(L_WARNING, "invalid NULL parameter");
		return -1;
	}

	paramValues[0] = email;
	paramValues[1] = password;

	paramLengths[0] = strlen(email);
	paramLengths[1] = strlen(password);

	result = PQexecPrepared(dbconn, "dao_fetch_account_apikey", 2, paramValues, paramLengths, NULL, 0);

	if (!result) {
		jlog(L_WARNING, "PQexec command failed: %s", PQerrorMessage(dbconn));
		return -1;
	}

	if (check_result_status(result) == -1) {
		PQclear(result);
		return -1;
	}

	tuples = PQntuples(result);
	fields = PQnfields(result);

	if (tuples > 0 && fields > 0) {
		*apikey = strdup(PQgetvalue(result, 0, 0));
	}

	jlog(L_DEBUG, "Tuples %d", tuples);
	jlog(L_DEBUG, "Fields %d", fields);

	PQclear(result);

	return 0;
}

int dao_fetch_client_id_by_apikey(char **client_id, char *apikey)
{
	const char *paramValues[1];
	int paramLengths[1];
	int tuples;
	int fields;
	PGresult *result = NULL;

	if (!client_id || !apikey) {
		jlog(L_WARNING, "invalid NULL parameter");
		return -1;
	}

	paramValues[0] = apikey;
	paramLengths[0] = strlen(apikey);

	result = PQexecPrepared(dbconn, "dao_fetch_client_id_by_apikey", 1, paramValues, paramLengths, NULL, 0);

	if (!result) {
		jlog(L_WARNING, "PQexec command failed: %s", PQerrorMessage(dbconn));
		return -1;
	}

	tuples = PQntuples(result);
	fields = PQnfields(result);

	if (tuples > 0 && fields > 0) {
		*client_id = strdup(PQgetvalue(result, 0, 0));
	}

	PQclear(result);

	return 0;
}

int dao_fetch_client_id(char **client_id, char *email, char *password)
{
	const char *paramValues[2];
	int paramLengths[2];
	int tuples;
	int fields;
	PGresult *result = NULL;

	if (!client_id || !email || !password) {
		jlog(L_WARNING, "invalid NULL parameter");
		return -1;
	}

	paramValues[0] = email;
	paramValues[1] = password;

	paramLengths[0] = strlen(email);
	paramLengths[1] = strlen(password);

	result = PQexecPrepared(dbconn, "dao_fetch_client_id", 2, paramValues, paramLengths, NULL, 0);

	if (!result) {
		jlog(L_WARNING, "PQexec command failed: %s", PQerrorMessage(dbconn));
		return -1;
	}

	if (check_result_status(result) == -1) {
		PQclear(result);
		return -1;
	}

	tuples = PQntuples(result);
	fields = PQnfields(result);

	if (tuples > 0 && fields > 0) {
		*client_id = strdup(PQgetvalue(result, 0, 0));
	}

	jlog(L_DEBUG, "Tuples %d", tuples);
	jlog(L_DEBUG, "Fields %d", fields);

	PQclear(result);

	return 0;
}

int dao_del_node(char *context_id, char *uuid)
{
	const char *paramValues[2];
	int paramLengths[2];
	PGresult *result;

	if (!context_id || !uuid) {
		jlog(L_WARNING, "invalid parameter");
		return -1;
	}

	paramValues[0] = context_id;
	paramValues[1] = uuid;

	paramLengths[0] = strlen(context_id);
	paramLengths[1] = strlen(uuid);

	result = PQexecPrepared(dbconn, "dao_del_node", 2, paramValues, paramLengths, NULL, 0);

	if (!result) {
		jlog(L_WARNING, "PQexec command failed: %s", PQerrorMessage(dbconn));
		PQclear(result);
		return -1;
	}

	PQclear(result);

	return 0;
}

int dao_del_node_by_context_id(char *context_id)
{
	const char *paramValues[1];
	int paramLengths[1];
	PGresult *result;

	if (!context_id) {
		jlog(L_WARNING, "invalid parameter");
		return -1;
	}

	paramValues[0] = context_id;
	paramLengths[0] = strlen(context_id);

	result = PQexecPrepared(dbconn, "dao_del_node_by_context_id", 1, paramValues, paramLengths, NULL, 0);

	if (!result) {
		jlog(L_WARNING, "PQexec command failed: %s", PQerrorMessage(dbconn));
		PQclear(result);
		return -1;
	}

	PQclear(result);

	return 0;
}

int dao_add_node(char *context_id, char *uuid, char *certificate, char *privatekey, char *provcode, char *description, char *ipaddress)
{
	const char *paramValues[7];
	int paramLengths[7];
	PGresult *result;

	if (!context_id || !uuid || !certificate || !privatekey || !provcode || !ipaddress) {
		jlog(L_WARNING, "invalid NULL parameter");
		return -1;
	}

	paramValues[0] = context_id;
	paramValues[1] = uuid;
	paramValues[2] = certificate;
	paramValues[3] = privatekey;
	paramValues[4] = provcode;
	paramValues[5] = description;
	paramValues[6] = ipaddress;

	paramLengths[0] = strlen(context_id);
	paramLengths[1] = strlen(uuid);
	paramLengths[2] = strlen(certificate);
	paramLengths[3] = strlen(privatekey);
	paramLengths[4] = strlen(provcode);
	paramLengths[5] = strlen(description);
	paramLengths[6] = strlen(ipaddress);

	result = PQexecPrepared(dbconn, "dao_add_node", 7, paramValues, paramLengths, NULL, 0);

	if (!result) {
		jlog(L_WARNING, "PQexec command failed: %s", PQerrorMessage(dbconn));
		return -1;
	}

	if (check_result_status(result) == -1) {
		PQclear(result);
		return -1;
	}

	PQclear(result);

	return 0;
}

int dao_del_context(char *client_id, char *context_id)
{
	const char *paramValues[2];
	int paramLengths[2];
	PGresult *result;

	if (!context_id || !client_id) {
		jlog(L_WARNING, "invalid parameter");
		return -1;
	}

	paramValues[0] = client_id;
	paramLengths[0] = strlen(client_id);

	paramValues[1] = context_id;
	paramLengths[1] = strlen(context_id);

	result = PQexecPrepared(dbconn, "dao_del_context", 2, paramValues, paramLengths, NULL, 0);

	if (!result) {
		jlog(L_WARNING, "PQexec command failed: %s", PQerrorMessage(dbconn));
		PQclear(result);
		return -1;
	}

	check_result_status(result);

	PQclear(result);

	return 0;
}

int dao_add_context(char *client_id,
			char *description,
			char *network,
			char *embassy_certificate,
			char *embassy_privatekey,
			char *embassy_serial,
			char *passport_certificate,
			char *passport_privatekey,
			const unsigned char *ippool,
			size_t pool_size)
{
	const char *paramValues[10];
	int paramLengths[10];
	PGresult *result;
	unsigned char *ippool_str;
	size_t ippool_str_len;

	if (!client_id || !description || !network ||
		!embassy_certificate || !embassy_privatekey || !embassy_serial ||
		!passport_certificate || !passport_privatekey) {

		jlog(L_WARNING, "invalid NULL parameter");
		return -1;
	}

	ippool_str = PQescapeByteaConn(dbconn, ippool, pool_size, &ippool_str_len);

	paramValues[0] = client_id;
	paramValues[1] = description;
	paramValues[2] = network;
	paramValues[3] = embassy_certificate;
	paramValues[4] = embassy_privatekey;
	paramValues[5] = embassy_serial;
	paramValues[6] = passport_certificate;
	paramValues[7] = passport_privatekey;
	paramValues[8] = (char *)ippool_str;

	paramLengths[0] = strlen(client_id);
	paramLengths[1] = strlen(description);
	paramLengths[2] = strlen(network);
	paramLengths[3] = strlen(embassy_certificate);
	paramLengths[4] = strlen(embassy_privatekey);
	paramLengths[5] = strlen(embassy_serial);
	paramLengths[6] = strlen(passport_certificate);
	paramLengths[7] = strlen(passport_privatekey);
	paramLengths[8] = ippool_str_len;

	result = PQexecPrepared(dbconn, "dao_add_context", 9, paramValues, paramLengths, NULL, 0);
	if (!result) {
		jlog(L_WARNING, "PQexec command failed: %s", PQerrorMessage(dbconn));
		return -1;
	}

	PQfreemem(ippool_str);

	if (check_result_status(result) == -1) {
		PQclear(result);
		return -2;
	}

	PQclear(result);

	return 0;
}

int dao_fetch_context_ippool(char *context_id, unsigned char **ippool)
{
	const char *paramValues[1];
	int paramLengths[1];
	unsigned char *ippool_ptr;
	size_t ippool_size;
	PGresult *result;

	if (!context_id) {
		jlog(L_WARNING, "invalid NULL parameter");
		return -1;
	}

	paramValues[0] = context_id;
	paramLengths[0] = strlen(context_id);

	result = PQexecPrepared(dbconn, "dao_fetch_context_ippool", 1, paramValues, paramLengths, NULL, 0);

	if (!result) {
		jlog(L_WARNING, "PQexec command failed: %s", PQerrorMessage(dbconn));
		return -1;
	}

	if (check_result_status(result) == -1) {
		PQclear(result);
		return -1;
	}

	int tuples, fields;
	tuples = PQntuples(result);
	fields = PQnfields(result);

	if (tuples > 0 && fields > 0) {
		ippool_ptr = (unsigned char *)PQgetvalue(result, 0, 0);
		ippool_size = PQgetlength(result, 0, 0);
		*ippool = PQunescapeBytea(ippool_ptr, &ippool_size);
	} else {
		PQclear(result);
		return -1;
	}

	PQclear(result);

	return 0;
}

int dao_fetch_network_id(char **context_id, char *client_id, char *description)
{
	const char *paramValues[2];
	int paramLengths[2];
	PGresult *result;

	if (!client_id || !description) {
		jlog(L_WARNING, "invalid NULL parameter");
		return -1;
	}

	paramValues[0] = client_id;
	paramValues[1] = description;

	paramLengths[0] = strlen(client_id);
	paramLengths[0] = strlen(description);

	result = PQexecPrepared(dbconn, "dao_fetch_network_id", 2, paramValues, paramLengths, NULL, 0);

	if (!result) {
		jlog(L_WARNING, "PQexec command failed: %s", PQerrorMessage(dbconn));
		return -1;
	}

	if (check_result_status(result) == -1) {
		PQclear(result);
		return -1;
	}

	int tuples, fields;
	tuples = PQntuples(result);
	fields = PQnfields(result);

	if (tuples > 0 && fields > 0) {
		*context_id = strdup(PQgetvalue(result, 0, 0));
	} else {
		PQclear(result);
		return -1;
	}

	PQclear(result);

	return 0;
}

int dao_fetch_context_embassy(char *context_id,
			char **certificate,
			char **privatekey,
			char **serial,
			unsigned char **ippool)
{
	const char *paramValues[1];
	int paramLengths[1];
	PGresult *result;
	int tuples, fields;
	unsigned char *ippool_ptr;
	size_t ippool_size;

	if (!context_id || !certificate || !privatekey || !serial) {
		jlog(L_WARNING, "invalid NULL parameter");
		return -1;
	}

	paramValues[0] = context_id;
	paramLengths[0] = strlen(context_id);

	result = PQexecPrepared(dbconn, "dao_fetch_context_embassy", 1, paramValues, paramLengths, NULL, 0);

	if (!result) {
		jlog(L_WARNING, "PQexec command failed: %s", PQerrorMessage(dbconn));
		return -1;
	}

	if (check_result_status(result) == -1) {
		PQclear(result);
		return -1;
	}

	tuples = PQntuples(result);
	fields = PQnfields(result);

	if (tuples > 0 && fields == 4) {

		*certificate = strdup(PQgetvalue(result, 0, 0));
		*privatekey = strdup(PQgetvalue(result, 0, 1));
		*serial = strdup(PQgetvalue(result, 0, 2));

		ippool_ptr = (unsigned char *)PQgetvalue(result, 0, 3);
		ippool_size = PQgetlength(result, 0, 3);
		*ippool = PQunescapeBytea(ippool_ptr, &ippool_size);
	} else {
		PQclear(result);
		return -1;
	}

	PQclear(result);

	return 0;
}

int dao_update_context_ippool(char *context_id, unsigned char *ippool, int pool_size)
{
	const char *paramValues[2];
	int paramLengths[2];
	PGresult *result = NULL;
	unsigned char *ippool_str;
	size_t ippool_str_len;

	if (!context_id || !ippool) {
		jlog(L_WARNING, "invalid NULL parameter");
		return -1;
	}

	ippool_str = PQescapeByteaConn(dbconn, ippool, pool_size, &ippool_str_len);

	paramValues[0] = context_id;
	paramValues[1] = (char *)ippool_str;

	paramLengths[0] = strlen(context_id);
	paramLengths[1] = ippool_str_len;

	result = PQexecPrepared(dbconn, "dao_update_context_ippool", 2, paramValues, paramLengths, NULL, 1);

	PQfreemem(ippool_str);

	if (!result) {
		jlog(L_WARNING, "PQexec command failed: %s", PQerrorMessage(dbconn));
		return -1;
	}

	if (check_result_status(result) == -1) {
		PQclear(result);
		return -1;
	}

	PQclear(result);

	return 0;
}

int dao_update_embassy_serial(char *context_id, char *serial)
{
	const char *paramValues[2];
	int paramLengths[2];
	PGresult *result = NULL;

	if (!context_id || !serial) {
		jlog(L_WARNING, "invalid NULL parameter");
		return -1;
	}

	paramValues[0] = context_id;
	paramValues[1] = serial;

	paramLengths[0] = strlen(context_id);
	paramLengths[1] = strlen(serial);

	result = PQexecPrepared(dbconn, "dao_update_embassy_serial", 2, paramValues, paramLengths, NULL, 1);

	if (!result) {
		jlog(L_WARNING, "PQexec command failed: %s", PQerrorMessage(dbconn));
		return -1;
	}

	if (check_result_status(result) == -1) {
		PQclear(result);
		return -1;
	}

	PQclear(result);

	return 0;
}

int dao_fetch_embassy(char *context_id,
			char **certificate,
			char **private_key,
			char **issue_serial)
{
	PGresult *result;
	char fetch_req[512];

	snprintf(fetch_req, 512, "SELECT certificate, private_key, issue_serial "
				"FROM EMBASSY "
				"WHERE context_id = '%s';",
				context_id);

	jlog(L_DEBUG, "fetch_req: %s", fetch_req);

	result = PQexec(dbconn, fetch_req);
	*certificate = strdup(PQgetvalue(result, 0, 0));
	*private_key = strdup(PQgetvalue(result, 0, 1));
	*issue_serial = strdup(PQgetvalue(result, 0, 2));

	if (!result) {
		jlog(L_WARNING, "PQexec command failed: %s", PQerrorMessage(dbconn));
	}

	if (check_result_status(result) == -1) {
		PQclear(result);
		return -1;
	}

	PQclear(result);

	return 0;
}

void dao_reset_node_state()
{
	PGresult *result;

	result = PQexec(dbconn, "update node SET status = 0 where node.status = 1;");
	check_result_status(result);
}

int dao_fetch_node_sequence(uint32_t *context_id_list, uint32_t list_size, void *data, void (*cb_data_handler)(void *data, int remaining,
								char *uuid, char *contextId))
{
	PGresult *result;

	int cursor = 0;
	int total_size = 0;
	char *fetch_req = NULL;
	uint32_t i = 0;

	total_size = (5*list_size) + strlen("SELECT node.uuid, node.context_id FROM node WHERE node.context_id IN ();");
	fetch_req = calloc(1, total_size);
	cursor = snprintf(fetch_req, total_size, "SELECT node.uuid, node.context_id FROM node WHERE node.context_id IN (%d", context_id_list[0]);
	for (i = 1; i < list_size; i++) {
		cursor += snprintf(fetch_req+cursor, total_size-cursor, ",%d", context_id_list[i]);
	}
	snprintf(fetch_req+cursor, total_size-cursor, ");");

	result = PQexec(dbconn, fetch_req);
	if (!result) {
		jlog(L_WARNING, "PQexec command failed: %s", PQerrorMessage(dbconn));
	}

	if (check_result_status(result) == -1) {
		PQclear(result);
		return -1;
	}

	int tuples;
	tuples = PQntuples(result);
	if (tuples == 0) {
		PQclear(result);
		free(fetch_req);
		return -1;
	}

	int j;
	for (j = 0; j < tuples; j++) {
		cb_data_handler(data, tuples - j - 1, PQgetvalue(result, j, 0), PQgetvalue(result, j, 1));
	}

	PQclear(result);
	free(fetch_req);

	return 0;
}

int dao_fetch_node_uuid_netid(void *arg, void (*cb_data_handler)(void *, int, char *, char *))
{
	int		 i;
	int		 tuples;
	PGresult	*result;

	if ((result = PQexecPrepared(dbconn, "dao_fetch_node_uuid_netid", 0, NULL, NULL, NULL, 0)) == NULL) {
		jlog(L_WARNING, "PQexec command failed: %s\n", PQerrorMessage(dbconn));
		return -1;
	}

	if (check_result_status(result) == -1) {
		PQclear(result);
		return -1;
	}

	tuples = PQntuples(result);
	for (i = 0; i < tuples; i++) {
		cb_data_handler(arg, tuples - i - 1,
			PQgetvalue(result, i, 0),
			PQgetvalue(result, i, 1));
	}

	PQclear(result);

	return 0;


}

int dao_fetch_node_ip(char *context_id, char *uuid, char **ipaddress)
{
	const char *paramValues[2];
	int paramLengths[2];
	PGresult *result;

	if (!context_id || !uuid) {
		jlog(L_WARNING, "invalid NULL parameter");
		return -1;
	}

	paramValues[0] = context_id;
	paramLengths[0] = strlen(context_id);

	paramValues[1] = uuid;
	paramLengths[1] = strlen(uuid);

	result = PQexecPrepared(dbconn, "dao_fetch_node_ip", 2, paramValues, paramLengths, NULL, 0);
	if (!result) {
		jlog(L_WARNING, "PQexec command failed: %s", PQerrorMessage(dbconn));
		return -1;
	}

	if (check_result_status(result) == -1) {
		PQclear(result);
		return -1;
	}

	int tuples, fields;
	tuples = PQntuples(result);
	fields = PQnfields(result);

	if (tuples > 0 && fields > 0) {
		*ipaddress = strdup(PQgetvalue(result, 0, 0));
	} else {
		PQclear(result);
		return -1;
	}

	PQclear(result);

	return 0;
}

int dao_fetch_node_from_context_id(char *context_id, void *data, int (*cb_data_handler)(void *data,
								char *uuid,
								char *description,
								char *provcode,
								char *ipaddress,
								char *status))
{
	const char *paramValues[1];
	int paramLengths[1];
	int tuples;
	PGresult *result;

	if (!context_id) {
		jlog(L_WARNING, "invalid NULL parameter");
		return -1;
	}

	paramValues[0] = context_id;
	paramLengths[0] = strlen(context_id);

	result = PQexecPrepared(dbconn, "dao_fetch_node_from_context_id", 1, paramValues, paramLengths, NULL, 0);

	if (!result) {
		jlog(L_WARNING, "PQexec command failed: %s", PQerrorMessage(dbconn));
		return -1;
	}

	if (check_result_status(result) == -1) {
		PQclear(result);
		return -1;
	}

	tuples = PQntuples(result);

	int i;
	for (i = 0; i < tuples; i++) {
		cb_data_handler(data,
			PQgetvalue(result, i, 0),
			PQgetvalue(result, i, 1),
			PQgetvalue(result, i, 2),
			PQgetvalue(result, i, 3),
			PQgetvalue(result, i, 4));
	}

	PQclear(result);

	return 0;
}

int dao_fetch_node_from_provcode(char *provcode,
					char **certificate,
					char **private_key,
					char **trustedcert,
					char **ipAddress)
{
	PGresult *result;
	char fetch_req[1024];

	snprintf(fetch_req, 1024, 	"SELECT node.certificate, "
						"node.privatekey, "
						"node.ipaddress, "
						"context.embassy_certificate as trustedcert "
					"FROM	node, context "
					"WHERE	provcode = '%s' "
					"AND	node.context_id = context.id;",
					provcode);

	result = PQexec(dbconn, fetch_req);

	if (!result) {
		jlog(L_WARNING, "PQexec command failed: %s", PQerrorMessage(dbconn));
	}

	int tuples, fields;
	tuples = PQntuples(result);
	fields = PQnfields(result);

	if (tuples > 0 && fields == 4) {
		*certificate = strdup(PQgetvalue(result, 0, 0));
		*private_key = strdup(PQgetvalue(result, 0, 1));
		*ipAddress = strdup(PQgetvalue(result, 0, 2));
		*trustedcert = strdup(PQgetvalue(result, 0, 3));
	} else {
		PQclear(result);
		return -1;
	}

	if (check_result_status(result) == -1) {
		PQclear(result);
		return -1;
	}

	PQclear(result);

	return 0;
}

int dao_fetch_networks_by_client_id(
	char *client_id,
	void *data,
	int (*cb_data_handler)(void *data,
		char *description))
{
	const char *paramValues[1];
	int paramLengths[1];
	int tuples;
	PGresult *result;

	if (!client_id) {
		jlog(L_WARNING, "invalid parameter");
		return -1;
	}

	paramValues[0] = client_id;
	paramLengths[0] = strlen(client_id);

	result = PQexecPrepared(dbconn, "dao_fetch_networks_by_client_id", 1, paramValues, paramLengths, NULL, 0);

	if (!result) {
		jlog(L_WARNING, "PQexec command failed: %s", PQerrorMessage(dbconn));
	}

	if (check_result_status(result) == -1) {
		PQclear(result);
		return -1;
	}

	tuples = PQntuples(result);

	int i;
	for (i = 0; i < tuples; i++) {
		cb_data_handler(data,
			PQgetvalue(result, i, 0));
	}

	PQclear(result);

	return 0;
}

int dao_fetch_network_by_client_id_desc(char *client_id, char *description,
					void *data, int (*cb_data_handler)(void *data,
					char *id,
					char *description,
					char *client_id,
					char *network,
					char *netmask,
					char *serverCert,
					char *serverPrivkey,
					char *trustedCert))

{
	const char *paramValues[2];
	int paramLengths[2];
	int tuples;
	PGresult *result;

	if (!client_id) {
		jlog(L_WARNING, "invalid NULL parameter");
		return -1;
	}

	paramValues[0] = client_id;
	paramValues[1] = description;
	paramLengths[0] = strlen(client_id);
	paramLengths[1] = strlen(description);

	result = PQexecPrepared(dbconn, "dao_fetch_network_by_client_id_desc", 2, paramValues, paramLengths, NULL, 0);

	if (!result) {
		jlog(L_WARNING, "PQexec command failed: %s", PQerrorMessage(dbconn));
	}

	if (check_result_status(result) == -1) {
		PQclear(result);
		return -1;
	}

	tuples = PQntuples(result);

	int i;
	for (i = 0; i < tuples; i++) {

		cb_data_handler(data,
			PQgetvalue(result, i, 0),
			PQgetvalue(result, i, 1),
			PQgetvalue(result, i, 2),
			PQgetvalue(result, i, 3),
			PQgetvalue(result, i, 4),
			PQgetvalue(result, i, 5),
			PQgetvalue(result, i, 6),
			PQgetvalue(result, i, 7));
	}

	PQclear(result);

	return 0;
}
int dao_fetch_context(void *data, void (*cb_data_handler)(void *data, int remaining,
							char *id,
							char *description,
							char *client_id,
							char *network,
							char *netmask,
							char *serverCert,
							char *serverPrivkey,
							char *trustedCert))
{
	int tuples;
	PGresult *result;

	result = PQexecPrepared(dbconn, "dao_fetch_context", 0, NULL, NULL, NULL, 0);

	if (!result) {
		jlog(L_WARNING, "PQexec command failed: %s", PQerrorMessage(dbconn));
		return -1;
	}

	if (check_result_status(result) == -1) {
		PQclear(result);
		return -1;
	}

	tuples = PQntuples(result);
	if (tuples == 0) {
		PQclear(result);
		return 0;
	}

	int i;
	for (i = 0; i < tuples; i++) {
		cb_data_handler(data, tuples - i - 1,
			PQgetvalue(result, i, 0),
			PQgetvalue(result, i, 1),
			PQgetvalue(result, i, 2),
			PQgetvalue(result, i, 3),
			PQgetvalue(result, i, 4),
			PQgetvalue(result, i, 5),
			PQgetvalue(result, i, 6),
			PQgetvalue(result, i, 7));
	}

	PQclear(result);

	return 0;
}
