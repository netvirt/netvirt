/*
 * Dynamic Network Directory Service
 * Copyright (C) 2010-2012 Nicolas Bouliane
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; version 2
 * of the License.
 *
 */

/* gcc dao.c -lpq
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <postgresql/libpq-fe.h>

#include "dao.h"

PGconn *dbconn = NULL;

int dao_connect(char *host, char *username, char *password, char *dbname)
{
	char conn_str[128];
	snprintf(conn_str, sizeof(conn_str), "dbname = %s user = %s password = %s host = %s",
						dbname, username, password, host); 

	dbconn = PQconnectdb(conn_str);

	if (PQstatus(dbconn) != CONNECTION_OK) {
		fprintf(stderr, "Connection to database failed: %s", PQerrorMessage(dbconn));
		PQfinish(dbconn);

		return -1;
	} else {
		printf("connected ok\n");
	}

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
			char *postal_code)
{

	PGresult *result;
	char insert_req[512];

	snprintf(insert_req, 512, "INSERT INTO client "
				"(firstname, lastname, email, company, phone, country, state_province, city, postal_code, status) "
				"VALUES ('%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', 1);",
				firstname, lastname, email, company, phone, country, state_province, city, postal_code);

	printf("insert_req: %s\n", insert_req);

	result = PQexec(dbconn, insert_req);

	if (!result) {
		printf("PQexec command failed, no error code\n");
	}

	switch (PQresultStatus(result)) {
	case PGRES_COMMAND_OK:
		printf("command executed ok, %s rows affected\n", PQcmdTuples(result));
		break;
	case PGRES_TUPLES_OK:
		printf("query may have returned data\n");
		break;
	default:
		printf("command failed with code %s, error message %s\n",
			PQresStatus(PQresultStatus(result)),
			PQresultErrorMessage(result));
		break;
	}

	return 0;
}

int dao_fetch_context(char **id,
			char **topology_id,
			char **description,
			char **network,
			char **netmask,
			char **serverCert,
			char **serverPrivkey,
			char **trustedCert)
{
	PGresult *result;
	result = PQexec(dbconn, "SELECT id, topology_id, description, host(network), netmask(network),\
					passport_server.certificate, \
					passport_server.private_key, embassy.certificate \
				FROM context, subnet, embassy, passport_server \
				WHERE id = subnet.context_id \
				AND id = embassy.context_id \
				AND id = passport_server.context_id;");

	if (!result) {
		printf("PQexec command failed, no error code\n");
	}

	switch (PQresultStatus(result)) {
	case PGRES_COMMAND_OK:
		printf("command executed ok, %s rows affected\n", PQcmdTuples(result));
		break;
	case PGRES_TUPLES_OK:
		printf("query may have returned data\n");
		break;
	default:
		printf("command failed with code %s, error message %s\n",
			PQresStatus(PQresultStatus(result)),
			PQresultErrorMessage(result));
		break;
	}

	int tuples, fields;
	tuples = PQntuples(result);
	fields = PQnfields(result);

	printf("Tuples %d\n", tuples);
	printf("Fields %d\n", fields);

	int i;
	for (i = 0; i<fields; i++) {
		printf("%s | %s\n", PQfname(result, i), PQgetvalue(result, 0, i));
	}

	*id = strdup(PQgetvalue(result, 0, 0));
	*topology_id = strdup(PQgetvalue(result, 0, 1));
	*description = strdup(PQgetvalue(result, 0, 2));
	*network = strdup(PQgetvalue(result, 0, 3));
	*netmask = strdup(PQgetvalue(result, 0, 4));
	*serverCert = strdup(PQgetvalue(result, 0, 5));
	*serverPrivkey = strdup(PQgetvalue(result, 0, 6));
	*trustedCert = strdup(PQgetvalue(result, 0, 7));

	return 0;
}

#if 0
int main(int argc, char *argv[])
{
	dao_connect(argv[1], argv[2], argv[3], argv[4]);
//	dao_fetch_context();

	dao_add_client("firstname",
			"lastname",
			"email",
			"company",
			"phone",
			"country",
			"state_province",
			"city",
			"postal_code");

}
#endif
