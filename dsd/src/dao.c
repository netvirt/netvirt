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

/* gcc dao.c -lpq -ldnds -lossp-uuid
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <dnds/pki.h>
#include <postgresql/libpq-fe.h>

#include <ossp/uuid.h>

#include "dao.h"

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

int dao_add_subnet(char *context_id, char *network)
{
	PGresult *result;
	char insert_req[128];

	snprintf(insert_req, 128, "INSERT INTO SUBNET "
				"(context_id, network) "
				"VALUES ('%s', '%s');",
				context_id, network);

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

int dao_add_passport_client(char *context_id, char *uuid, char *certificate, char *private_key)
{
	PGresult *result;
	char insert_req[4000];

	snprintf(insert_req, 4000, "INSERT INTO PASSPORT_CLIENT "
				"(context_id, uuid, certificate, private_key, status) "
				"VALUES ('%s', '%s', '%s', '%s', 0);",
				context_id, uuid, certificate, private_key);

//	printf("insert_req: %s\n", insert_req);

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

int dao_add_passport_server(char *context_id, char *common_name, char *certificate, char *private_key)
{
	PGresult *result;
	char insert_req[4000];

	snprintf(insert_req, 4000, "INSERT INTO PASSPORT_SERVER "
				"(context_id, common_name, certificate, private_key, status) "
				"VALUES ('%s', '%s', '%s', '%s', 0);",
				context_id, common_name, certificate, private_key);

//	printf("insert_req: %s\n", insert_req);

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

int dao_add_embassy(char *context_id, char *certificate, char *private_key)
{
	PGresult *result;
	char insert_req[4000];

	snprintf(insert_req, 4000, "INSERT INTO EMBASSY "
				"(context_id, certificate, private_key, issue_serial) "
				"VALUES ('%s', '%s', '%s', 0);",
				context_id, certificate, private_key);

//	printf("insert_req: %s\n", insert_req);

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

int dao_add_network(int client_id, int context_id)
{
	PGresult *result;
	char insert_req[512];

	snprintf(insert_req, 512, "INSERT INTO NETWORK "
				"(client_id, context_id) "
				"VALUES ('%d', '%d');",
				client_id, context_id);
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

int dao_add_context(char *client_id, int topology_id, char *description)
{
	PGresult *result;
	char insert_req[512];

	snprintf(insert_req, 512, "INSERT INTO CONTEXT "
				"(client_id, topology_id, description) "
				"VALUES ('%s', '%d', '%s');",
				client_id, topology_id, description);

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

int dao_fetch_context_id(char **context_id, char *client_id, char *description)
{
	PGresult *result;
	char fetch_req[512];

	snprintf(fetch_req, 512, "SELECT id "
				"FROM CONTEXT "
				"WHERE client_id = '%s' "
				"AND description = '%s';",
				client_id, description);

	result = PQexec(dbconn, fetch_req);
	*context_id = strdup(PQgetvalue(result, 0, 0));

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
}

int dao_fetch_client_id(char **client_id, char *firstname, char *lastname, char *email)
{
	PGresult *result;
	char fetch_req[512];

	snprintf(fetch_req, 512, "SELECT id "
				"FROM CLIENT "
				"WHERE firstname = '%s' "
				"AND lastname = '%s' "
				"AND email = '%s';",
				firstname, lastname, email);

	result = PQexec(dbconn, fetch_req);
	*client_id = strdup(PQgetvalue(result, 0, 0));

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

}

int dao_update_embassy_issue_serial(char *context_id, uint32_t issue_serial)
{
	PGresult *result;
	char update_req[256];

	snprintf(update_req, 256, "UPDATE embassy "
				"SET issue_serial = '%d' "
				"WHERE context_id = '%s';",
				issue_serial, context_id);

	printf("update_req: %s\n", update_req);

	result = PQexec(dbconn, update_req);

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

	printf("fetch_req: %s\n", fetch_req);

	result = PQexec(dbconn, fetch_req);
	*certificate = strdup(PQgetvalue(result, 0, 0));
	*private_key = strdup(PQgetvalue(result, 0, 1));
	*issue_serial = strdup(PQgetvalue(result, 0, 2));

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

	char *client_id = NULL;
	dao_fetch_client_id(&client_id, "firstname", "lastname", "email");

	printf("client_id: %s\n", client_id);

	dao_add_context(client_id, 1, "description");

	char *context_id = NULL;
	dao_fetch_context_id(&context_id, client_id, "description");

	printf("context_id: %s\n", context_id);

	//dao_add_network(1008, 3);

	/* DSD certificate */

	pki_init();

	int exp_delay;
	exp_delay = pki_expiration_delay(50);

	digital_id_t *dsd_id;

	dsd_id = pki_digital_id("embassy", "CA", "Quebec", "Levis", "info@demo.com", "DNDS");

	embassy_t *emb;
	emb = pki_embassy_new(dsd_id, exp_delay);

	char *cert_ptr; long size;
	char *pvkey_ptr;

	pki_write_certificate_in_mem(emb->certificate, &cert_ptr, &size);
	pki_write_privatekey_in_mem(emb->keyring, &pvkey_ptr, &size);

	dao_add_embassy(context_id, cert_ptr, pvkey_ptr);

	free(cert_ptr);
	free(pvkey_ptr);

	/* DND certificate */

	digital_id_t *dnd_id;
	dnd_id = pki_digital_id("dnd", "CA", "Quebec", "Levis", "info@demo.com", "DNDS");

	passport_t *dnd_passport;
	dnd_passport = pki_embassy_deliver_passport(emb, dnd_id, exp_delay);

	pki_write_certificate_in_mem(dnd_passport->certificate, &cert_ptr, &size);
	pki_write_privatekey_in_mem(dnd_passport->keyring, &pvkey_ptr, &size);

	dao_add_passport_server(context_id, "dnd@4", cert_ptr, pvkey_ptr);

	free(cert_ptr);
	free(pvkey_ptr);

	/* DNC certificate */

	// fetch embassy
	char *certificate, *private_key, *serial;
	embassy_t *f_emb;
	dao_fetch_embassy(context_id, &certificate, &private_key, &serial);

	f_emb = pki_embassy_load_from_memory(certificate, private_key, atoi(serial));


	char *uuid;
	uuid = uuid_v4();

	char common_name[256];
	snprintf(common_name, sizeof(common_name), "dnc-%s@4", uuid);
	printf("common_name: %s\n", common_name);

	digital_id_t *dnc_id;
	dnc_id = pki_digital_id(common_name, "CA", "Quebec", "Levis", "info@demo.com", "DNDS");

	passport_t *dnc_passport;
	dnc_passport = pki_embassy_deliver_passport(f_emb, dnc_id, exp_delay);

	pki_write_certificate_in_mem(dnc_passport->certificate, &cert_ptr, &size);
	pki_write_privatekey_in_mem(dnc_passport->keyring, &pvkey_ptr, &size);

	dao_add_passport_client(context_id, uuid, cert_ptr, pvkey_ptr);

	dao_update_embassy_issue_serial(context_id, f_emb->serial);

	free(cert_ptr);
	free(pvkey_ptr);

	/* * * */

	dao_add_subnet(context_id, "44.128.0.0/16");
}
#endif
