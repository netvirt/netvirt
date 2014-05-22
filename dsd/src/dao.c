/*
 * Dynamic Network Directory Service
 * Copyright (C) 2009-2014
 * Nicolas J. Bouliane <nib@dynvpn.com>
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

/* gcc dao.c -lpq -ldnds -lossp-uuid
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <postgresql/libpq-fe.h>
#include <ossp/uuid.h>

#include <logger.h>

#include "dsd.h"
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
			"(firstname, lastname, email, company, phone, country, state_province, city, postal_code, password) "
			"VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, crypt($10, gen_salt('bf')));",
			0,
			NULL);

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

	if (result == NULL)
		goto error;
	PQclear(result);

	result = PQprepare(dbconn,
			"dao_add_context",
			"INSERT INTO CONTEXT "
			"(client_id, description, topology_id, network, "
				"embassy_certificate, embassy_privatekey, embassy_serial, "
				"passport_certificate, passport_privatekey, ippool)"
			"VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10::bytea);",
			0,
			NULL);

	if (result == NULL)
		goto error;
	PQclear(result);

	result = PQprepare(dbconn,
			"dao_fetch_context_id",
			"SELECT id "
			"FROM CONTEXT "
			"WHERE client_id = $1 "
			"AND description = $2;",
			0,
			NULL);
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

	if (result == NULL)
		goto error;
	PQclear(result);

	result = PQprepare(dbconn,
			"dao_fetch_context_by_client_id",
			"SELECT id, topology_id, description, client_id, host(network), netmask(network), passport_certificate, passport_privatekey, embassy_certificate "
			"FROM context "
			"WHERE client_id = $1;",
			0,
			NULL);

	if (result == NULL)
		goto error;
	PQclear(result);

	result = PQprepare(dbconn,
			"dao_fetch_context_by_client_id_desc",
			"SELECT id, topology_id, description, client_id, host(network), netmask(network), passport_certificate, passport_privatekey, embassy_certificate "
			"FROM context "
			"WHERE client_id = $1 and description = $2;",
			0,
			NULL);

	if (result == NULL)
		goto error;
	PQclear(result);

	result = PQprepare(dbconn,
			"dao_fetch_context",
			"SELECT id, topology_id, description, client_id, host(network), netmask(network), passport_certificate, passport_privatekey, embassy_certificate "
			"FROM context;",
			0,
			NULL);

	if (result == NULL)
		goto error;
	PQclear(result);

	result = PQprepare(dbconn,
			"dao_fetch_node_from_context_id",
			"SELECT uuid, description, provcode, ipaddress "
			"FROM node "
			"WHERE context_id = $1;",
			0,
			NULL);

	if (result == NULL)
		goto error;
	PQclear(result);

	return 0;

error:
	jlog(L_WARNING, "PQprepare error: %s", PQerrorMessage(dbconn));
	return -1;
}

int dao_connect(struct dsd_cfg *dsd_cfg)
{
	char conn_str[128];
	snprintf(conn_str, sizeof(conn_str), "dbname = %s user = %s password = %s host = %s",
						dsd_cfg->db_name, dsd_cfg->db_user, dsd_cfg->db_pwd, dsd_cfg->db_host);

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

int dao_add_client(char *firstname,
			char *lastname,
			char *email,
			char *company,
			char *phone,
			char *country,
			char *state_province,
			char *city,
			char *postal_code,
			char *password)
{

	const char *paramValues[10];
	int paramLengths[10];
	PGresult *result = NULL;

	if (!firstname || !lastname || !email || !company || !phone ||
		!country || !state_province || !city || !postal_code || !password) {

		jlog(L_WARNING, "invalid NULL parameter");
		return -1;
	}

	paramValues[0] = firstname;
	paramValues[1] = lastname;
	paramValues[2] = email;
	paramValues[3] = company;
	paramValues[4] = phone;
	paramValues[5] = country;
	paramValues[6] = state_province;
	paramValues[7] = city;
	paramValues[8] = postal_code;
	paramValues[9] = password;

	paramLengths[0] = strlen(firstname);
	paramLengths[1] = strlen(lastname);
	paramLengths[2] = strlen(email);
	paramLengths[3] = strlen(company);
	paramLengths[4] = strlen(phone);
	paramLengths[5] = strlen(country);
	paramLengths[6] = strlen(state_province);
	paramLengths[7] = strlen(city);
	paramLengths[8] = strlen(postal_code);
	paramLengths[9] = strlen(password);

	result = PQexecPrepared(dbconn, "dao_add_client", 10, paramValues, paramLengths, NULL, 1);

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
		*client_id = PQgetvalue(result, 0, 0);
	}

	jlog(L_DEBUG, "Tuples %d", tuples);
	jlog(L_DEBUG, "Fields %d", fields);

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

	return 0;
}

int dao_add_context(char *client_id,
			char *description,
			char *topology_id,
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

	if (!client_id || !description || !topology_id || !network ||
		!embassy_certificate || !embassy_privatekey || !embassy_serial ||
		!passport_certificate || !passport_privatekey) {

		jlog(L_WARNING, "invalid NULL parameter");
		return -1;
	}

	ippool_str = PQescapeByteaConn(dbconn, ippool, pool_size, &ippool_str_len);

	paramValues[0] = client_id;
	paramValues[1] = description;
	paramValues[2] = topology_id;
	paramValues[3] = network;
	paramValues[4] = embassy_certificate;
	paramValues[5] = embassy_privatekey;
	paramValues[6] = embassy_serial;
	paramValues[7] = passport_certificate;
	paramValues[8] = passport_privatekey;
	paramValues[9] = (char *)ippool_str;

	paramLengths[0] = strlen(client_id);
	paramLengths[1] = strlen(description);
	paramLengths[2] = strlen(topology_id);
	paramLengths[3] = strlen(network);
	paramLengths[4] = strlen(embassy_certificate);
	paramLengths[5] = strlen(embassy_privatekey);
	paramLengths[6] = strlen(embassy_serial);
	paramLengths[7] = strlen(passport_certificate);
	paramLengths[8] = strlen(passport_privatekey);
	paramLengths[9] = ippool_str_len;

	result = PQexecPrepared(dbconn, "dao_add_context", 10, paramValues, paramLengths, NULL, 0);
	if (!result) {
		jlog(L_WARNING, "PQexec command failed: %s", PQerrorMessage(dbconn));
		return -1;
	}

	PQfreemem(ippool_str);

	if (check_result_status(result) == -1) {
		PQclear(result);
		return -1;
	}

	PQclear(result);

	return 0;
}

int dao_fetch_context_id(char **context_id, char *client_id, char *description)
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

	result = PQexecPrepared(dbconn, "dao_fetch_context_id", 2, paramValues, paramLengths, NULL, 0);

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
		*context_id = PQgetvalue(result, 0, 0);
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

int dao_fetch_node_from_context_id(char *context_id, void *data, int (*cb_data_handler)(void *data,
								char *uuid,
								char *description,
								char *provcode,
								char *ipaddress))
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
			strdup(PQgetvalue(result, i, 0)),
			strdup(PQgetvalue(result, i, 1)),
			strdup(PQgetvalue(result, i, 2)),
			strdup(PQgetvalue(result, i, 3)));
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

int dao_fetch_context_by_client_id(
	char *client_id,
	void *data,
	int (*cb_data_handler)(void *data,
		char *id,
		char *topology_id,
		char *description,
		char *client_id,
		char *network,
		char *netmask,
		char *serverCert,
		char *serverPrivkey,
		char *trustedCert))

{
	const char *paramValues[1];
	int paramLengths[1];
	int tuples;
	PGresult *result;

	if (!client_id) {
		jlog(L_WARNING, "invalid NULL parameter");
		return -1;
	}

	paramValues[0] = client_id;
	paramLengths[0] = strlen(client_id);

	result = PQexecPrepared(dbconn, "dao_fetch_context_by_client_id", 1, paramValues, paramLengths, NULL, 0);

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
			strdup(PQgetvalue(result, i, 0)),
			strdup(PQgetvalue(result, i, 1)),
			strdup(PQgetvalue(result, i, 2)),
			strdup(PQgetvalue(result, i, 3)),
			strdup(PQgetvalue(result, i, 4)),
			strdup(PQgetvalue(result, i, 5)),
			strdup(PQgetvalue(result, i, 6)),
			strdup(PQgetvalue(result, i, 7)),
			strdup(PQgetvalue(result, i, 8)));
	}

	PQclear(result);

	return 0;
}

int dao_fetch_context_by_client_id_desc(char *client_id, char *description,
					void *data, int (*cb_data_handler)(void *data,
					char *id,
					char *topology_id,
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

	result = PQexecPrepared(dbconn, "dao_fetch_context_by_client_id_desc", 2, paramValues, paramLengths, NULL, 0);

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
			strdup(PQgetvalue(result, i, 0)),
			strdup(PQgetvalue(result, i, 1)),
			strdup(PQgetvalue(result, i, 2)),
			strdup(PQgetvalue(result, i, 3)),
			strdup(PQgetvalue(result, i, 4)),
			strdup(PQgetvalue(result, i, 5)),
			strdup(PQgetvalue(result, i, 6)),
			strdup(PQgetvalue(result, i, 7)),
			strdup(PQgetvalue(result, i, 8)));
	}

	PQclear(result);

	return 0;
}
int dao_fetch_context(void *data, void (*cb_data_handler)(void *data,
							char *id,
							char *topology_id,
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
			PQgetvalue(result, i, 7),
			PQgetvalue(result, i, 8));
	}

	PQclear(result);

	return 0;
}

#if 0
int main(int argc, char *argv[])
{
	int ret = 0;

	/* 1- Connect and prepare statements */
	dao_connect(argv[1], argv[2], argv[3], argv[4]);
	dao_prepare_statements();
	dao_dump_statements();

	/* 2- Create a new client account */
	ret = dao_add_client("firstname",
			"lastname",
			"unique_email",
			"company",
			"phone",
			"country",
			"state_province",
			"city",
			"postal_code",
			"strong_password");

	printf("dao_add_client: %d\n", ret);

	char *client_id = NULL;

	ret = dao_fetch_client_id(&client_id, "unique_email", "strong_password");
	printf("dao_fetch_client_id: %d\n", ret);

	/* 3- Create a new context to the Client */

	pki_init();

	/* 3.1- Initialise embassy */
	int exp_delay;
	exp_delay = pki_expiration_delay(10);

	digital_id_t *embassy_id;
	embassy_id = pki_digital_id("embassy", "CA", "Quebec", "Levis", "info@dynvpn.com", "DNDS");

	embassy_t *emb;
	emb = pki_embassy_new(embassy_id, exp_delay);

	char *emb_cert_ptr; long size;
	char *emb_pvkey_ptr;

	pki_write_certificate_in_mem(emb->certificate, &emb_cert_ptr, &size);
	pki_write_privatekey_in_mem(emb->keyring, &emb_pvkey_ptr, &size);

	/* 3.2- Initialise server passport */

	digital_id_t *server_id;
	server_id = pki_digital_id("dnd", "CA", "Quebec", "Levis", "info@dynvpn.com", "DNDS");

	passport_t *dnd_passport;
	dnd_passport = pki_embassy_deliver_passport(emb, server_id, exp_delay);

	char *serv_cert_ptr;
	char *serv_pvkey_ptr;

	pki_write_certificate_in_mem(dnd_passport->certificate, &serv_cert_ptr, &size);
	pki_write_privatekey_in_mem(dnd_passport->keyring, &serv_pvkey_ptr, &size);

	char emb_serial[10];
	snprintf(emb_serial, sizeof(emb_serial), "%d", emb->serial);

	ret = dao_add_context(client_id,
				"unique_description",
				"1",
				"44.128.0.0/16",
				emb_cert_ptr,
				emb_pvkey_ptr,
				emb_serial,
				serv_cert_ptr,
				serv_pvkey_ptr);

	printf("emb->serial: %d\n", emb->serial);
	printf("dao_add_context: %d\n", ret);

	free(serv_cert_ptr);
	free(serv_pvkey_ptr);

	free(emb_cert_ptr);
	free(emb_pvkey_ptr);

	char *context_id = NULL;
	ret = dao_fetch_context_id(&context_id, client_id, "unique_description");
	printf("dao_fetch_context_id: %d\n", ret);
	printf("context_id: %s\n", context_id);

	/* 4- Add a node */

	char *serial = NULL;

	ret = dao_fetch_context_embassy(context_id, &emb_cert_ptr, &emb_pvkey_ptr, &serial);
	printf("dao_fetch_context_embassy: %d\n", ret);
	printf("serial: %s\n", serial);

	emb = pki_embassy_load_from_memory(emb_cert_ptr, emb_pvkey_ptr, atoi(serial));

	char *uuid;
	uuid = uuid_v4();

	char *provcode;
	provcode = uuid_v4();

	char common_name[256];
	snprintf(common_name, sizeof(common_name), "dnc-%s@%s", uuid, context_id);
	jlog(L_DEBUG, "common_name: %s", common_name);

	digital_id_t *node_ident;
	node_ident = pki_digital_id(common_name, "", "", "", "info@dynvpn.com", "DNDS");

	passport_t *node_passport;
	node_passport = pki_embassy_deliver_passport(emb, node_ident, exp_delay);

	char *node_cert_ptr;
	char *node_pvkey_ptr;

	pki_write_certificate_in_mem(node_passport->certificate, &node_cert_ptr, &size);
	pki_write_privatekey_in_mem(node_passport->keyring, &node_pvkey_ptr, &size);

	ret = dao_add_node(context_id, uuid, node_cert_ptr, node_pvkey_ptr, provcode);
	jlog(L_DEBUG, "dao_add_node: %d", ret);

	snprintf(emb_serial, sizeof(emb_serial), "%d", emb->serial);
	printf("emb->serial: %d\n", emb->serial);
	ret = dao_update_embassy_serial(context_id, emb_serial);
	jlog(L_DEBUG, "dao_update_embassy_serial: %d", ret);

	free(node_cert_ptr);
	free(node_pvkey_ptr);
}
#endif
