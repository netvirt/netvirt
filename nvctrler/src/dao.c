/*
 * NetVirt - Network Virtualization Platform
 * Copyright (C) 2009-2017 Mind4Networks inc.
 * Nicolas J. Bouliane <nib@m4nt.com>
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

#include <err.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <postgresql/libpq-fe.h>

PGconn *dbconn = NULL;

inline int
__attribute__((always_inline)) check_result_status(PGresult *result)
{
	if (result == NULL) {
		warnx("result is NULL: %s", PQerrorMessage(dbconn));
		return (-1);
	}

	switch (PQresultStatus(result)) {
	case PGRES_COMMAND_OK:
		warnx("command executed ok, %s rows affected", PQcmdTuples(result));
		break;
	case PGRES_TUPLES_OK:
		warnx("query may have returned data");
		break;
	default:
		warnx("command failed with code %s, error message %s",
			PQresStatus(PQresultStatus(result)),
			PQresultErrorMessage(result));
		return (-1);
	}
	return (0);
}

int
dao_prepare_statements()
{
	PGresult	*result = NULL;

	result = PQprepare(dbconn,
			"dao_client_create",
			"INSERT INTO client "
			"(email, password, apikey) "
			"VALUES (LOWER($1), crypt($2, gen_salt('bf')), crypt($3, gen_salt('bf')));",
			0,
			NULL);

	if (check_result_status(result) == -1)
		goto error;
	PQclear(result);

	result = PQprepare(dbconn,
			"dao_client_activate",
			"UPDATE client "
			"SET status = 1 "
			"WHERE apikey = crypt($1, apikey);",
			0,
			NULL);

	if (check_result_status(result) == -1)
		goto error;
	PQclear(result);

	result = PQprepare(dbconn,
			"dao_client_update_apikey",
			"UPDATE client "
			"set apikey = crypt($2, gen_salt('bf')) "
			"WHERE apikey = crypt($1, apikey) "
			"AND status = 1;",
			0,
			NULL);

	if (check_result_status(result) == -1)
		goto error;
	PQclear(result);

	result = PQprepare(dbconn,
			"dao_client_update_apikey2",
			"UPDATE client "
			"set apikey = crypt($3, gen_salt('bf')) "
			"WHERE LOWER(email) = LOWER($1) "
			"AND password = crypt($2, password) "
			"AND status = 1;",
			0,
			NULL);

	if (check_result_status(result) == -1)
		goto error;
	PQclear(result);

	result = PQprepare(dbconn,
			"dao_client_update_resetkey",
			"UPDATE client "
			"SET resetkey = crypt($2, gen_salt('bf')), "
			"resetdate = now() "
			"WHERE LOWER(email) = LOWER($1) "
			"AND (resetdate is NULL OR resetdate + interval '1hour' < now()) "
			"AND status = 1;",
			0,
			NULL);

	if (check_result_status(result) == -1)
		goto error;
	PQclear(result);

	result = PQprepare(dbconn,
			"dao_client_update_password",
			"UPDATE client "
			"SET password = crypt($3, gen_salt('bf')), "
			"resetdate = NULL "
			"WHERE resetkey = crypt($2, resetkey) "
			"AND LOWER(email) = LOWER($1) "
			"AND resetdate + interval '1day' > now() "
			"AND resetkey is not NULL "
			"AND status = 1;",
			0,
			NULL);

	if (check_result_status(result) == -1)
		goto error;
	PQclear(result);

	result = PQprepare(dbconn,
			"dao_client_get_id",
			"SELECT id "
			"FROM CLIENT "
			"WHERE apikey = crypt($1, apikey) "
			"AND status = 1;",
			0,
			NULL);

	if (check_result_status(result) == -1)
		goto error;
	PQclear(result);

	result = PQprepare(dbconn,
			"dao_network_create",
			"INSERT INTO network "
			"(client_id, uid, description, subnet, netmask, "
				"embassy_certificate, embassy_privatekey, embassy_serial, "
				"passport_certificate, passport_privatekey, ippool) "
			"VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11::bytea);",
			0,
			NULL);

	if (check_result_status(result) == -1)
		goto error;
	PQclear(result);

	result = PQprepare(dbconn,
			"dao_network_delete",
			"DELETE FROM network "
			"WHERE client_id = (SELECT id FROM client WHERE apikey = crypt($2, apikey) AND status = 1) "
			"AND description = $1;",
			0,
			NULL);

	if (check_result_status(result) == -1)
		goto error;
	PQclear(result);

	result = PQprepare(dbconn,
			"dao_network_list",
			"SELECT uid, description "
			"FROM network "
			"WHERE client_id = (SELECT id FROM client WHERE apikey = crypt($1, apikey) AND status = 1);",
			0,
			NULL);

	if (check_result_status(result) == -1)
		goto error;
	PQclear(result);

	result = PQprepare(dbconn,
			"dao_network_get_embassy",
			"SELECT embassy_certificate, embassy_privatekey, embassy_serial "
			"FROM network "
			"WHERE uid = $1;",
			0,
			NULL);

	if (check_result_status(result) == -1)
		goto error;
	PQclear(result);

	result = PQprepare(dbconn,
			"dao_network_get_ippool",
			"SELECT uid, subnet, netmask, ippool "
			"FROM network "
			"WHERE description = $1;",
			0,
			NULL);

	if (check_result_status(result) == -1)
		goto error;
	PQclear(result);

	result = PQprepare(dbconn,
			"dao_network_update_ippool",
			"UPDATE network "
			"SET ippool = $2::bytea "
			"WHERE uid = $1;",
			0,
			NULL);

	if (check_result_status(result) == -1)
		goto error;
	PQclear(result);

	result = PQprepare(dbconn,
			"dao_network_update_serial",
			"UPDATE network "
			"SET embassy_serial = $2 "
			"WHERE uid = $1;",
			0,
			NULL);

	if (check_result_status(result) == -1)
		goto error;
	PQclear(result);

	result = PQprepare(dbconn,
			"dao_node_create",
			"INSERT INTO node "
			"(network_uid, uid, provkey, description, ipaddress) "
			"VALUES ($1, $2, $3, $4, $5);",
			0,
			NULL);

	if (check_result_status(result) == -1)
		goto error;
	PQclear(result);

	result = PQprepare(dbconn,
			"dao_node_delete",
			"DELETE FROM node "
			"WHERE description = $1 "
			"AND node.network_uid IN (SELECT uid FROM network WHERE client_id = (SELECT id FROM client WHERE apikey = crypt($2, apikey) AND status = 1))",
			0,
			NULL);

	if (check_result_status(result) == -1)
		goto error;
	PQclear(result);

	result = PQprepare(dbconn,
			"dao_node_netinfo",
			"SELECT node.ipaddress, network.uid, network.subnet, network.netmask, network.ippool "
			"FROM node, network "
			"WHERE node.description = $1 "
			"AND node.network_uid IN (select uid FROM network WHERE client_id = (SELECT id FROM client WHERE apikey = crypt($2, apikey) AND status = 1))",
			0,
			NULL);

	result = PQprepare(dbconn,
			"dao_node_list",
			"SELECT node.uid, node.description, node.provkey, node.ipaddress, node.status "
			"FROM node, network "
			"WHERE network.uid = $1 "
			"AND network.client_id = (SELECT id FROM client WHERE apikey = crypt($2, apikey) AND status = 1);",
			0,
			NULL);

	if (check_result_status(result) == -1)
		goto error;
	PQclear(result);

	result = PQprepare(dbconn,
			"dao_node_delete_provkey",
			"UPDATE node "
			"SET provkey = $3 "  // FIXME set this to NULL
			"WHERE network_uid = $1 "
			"AND uid = $2 "
			"AND provkey = $3;",
			0,
			NULL);

	if (check_result_status(result) == -1)
		goto error;
	PQclear(result);

	result = PQprepare(dbconn,
			"dao_switch_network_list",
			"SELECT uid, passport_certificate, passport_privatekey, embassy_certificate "
			"FROM network;",
			0,
			NULL);

	if (check_result_status(result) == -1)
		goto error;
	PQclear(result);

	result = PQprepare(dbconn,
			"dao_node_listall",
			"SELECT network_uid, uid, description, ipaddress "
			"FROM node;",
			0,
			NULL);

	if (check_result_status(result) == -1)
		goto error;
	PQclear(result);


#if 0
	// XXX
	result = PQprepare(dbconn,
			"dao_fetch_client_id",
			"SELECT id "
			"FROM client "
			"WHERE LOWER(email) = LOWER($1) "
			"AND password = crypt($2, password);",
			0,
			NULL);

	if (check_result_status(result) == -1)
		goto error;
	PQclear(result);


	result = PQprepare(dbconn,
			"dao_fetch_network_ippool",
			"SELECT ippool "
			"FROM network "
			"WHERE uid = $1;",
			0,
			NULL);

	if (check_result_status(result) == -1)
		goto error;

	// XXX
	PQclear(result);
	result = PQprepare(dbconn,
			"dao_fetch_network_id",
			"SELECT id "
			"FROM network "
			"WHERE client_id = $1 "
			"AND uid = $2;",
			0,
			NULL);

	if (check_result_status(result) == -1)
		goto error;

	PQclear(result);
	result = PQprepare(dbconn,
			"dao_fetch_network_embassy",
			"SELECT embassy_certificate, embassy_privatekey, embassy_serial, ippool "
			"FROM network "
			"WHERE uid = $1;",
			0,
			NULL);

	if (check_result_status(result) == -1)
		goto error;

	PQclear(result);
	result = PQprepare(dbconn,
			"dao_del_node_by_network_uid",
			"DELETE FROM node "
			"WHERE network_uid = $1",
			0,
			NULL);

	if (check_result_status(result) == -1)
		goto error;

	PQclear(result);
	result = PQprepare(dbconn,
			"dao_update_node_status",
			"UPDATE node "
			"SET status = $3, ipsrc = $4 "
			"WHERE network_uid = $1 AND uid = $2;",
			0,
			NULL);

	if (check_result_status(result) == -1)
		goto error;

	PQclear(result);
	result = PQprepare(dbconn,
			"dao_update_network_ippool",
			"UPDATE network "
			"SET ippool = $2::bytea "
			"WHERE uid = $1;",
			0,
			NULL);

	if (check_result_status(result) == -1)
		goto error;

	PQclear(result);
	result = PQprepare(dbconn,
			"dao_update_embassy_serial",
			"UPDATE network "
			"SET embassy_serial = $2 "
			"WHERE uid = $1;",
			0,
			NULL);

	if (check_result_status(result) == -1)
		goto error;

	PQclear(result);

	// XXX client id ... and description..
	result = PQprepare(dbconn,
			"dao_fetch_network_by_client_id_desc",
			"SELECT id, description, client_id, subnet, netmask, passport_certificate, passport_privatekey, embassy_certificate "
			"FROM network "
			"WHERE client_id = $1 and description = $2;",
			0,
			NULL);

	if (check_result_status(result) == -1)
		goto error;
	PQclear(result);

	result = PQprepare(dbconn,
			"dao_fetch_network",
			"SELECT id, uid, description, client_id, host(cidr), netmask(cidr), passport_certificate, passport_privatekey, embassy_certificate "
			"FROM network;",
			0,
			NULL);

	if (check_result_status(result) == -1)
		goto error;
	PQclear(result);

	result = PQprepare(dbconn,
			"dao_fetch_node_uuid_networkuuid",
			"SELECT network_uid, uid "
			"FROM node",
			0,
			NULL);

	if (check_result_status(result) == -1)
		goto error;

	PQclear(result);
	result = PQprepare(dbconn,
			"dao_fetch_node_ip",
			"SELECT ipaddress "
			"FROM node "
			"WHERE network_uid = $1 "
			"AND uid = $2;",
			0,
			NULL);

	if (check_result_status(result) == -1)
		goto error;

	PQclear(result);
#endif


	return (0);
error:
	warnx("PQprepare error: %s", PQerrorMessage(dbconn));
	return (-1);
}

int
dao_init(const char *dbname, const char *dbuser, const char *dbpwd, const char *dbhost)
{
	char	 conn_str[128];

	snprintf(conn_str, sizeof(conn_str), "dbname = %s user = %s password = %s host = %s",
	    dbname, dbuser, dbpwd, dbhost);

	dbconn = PQconnectdb(conn_str);

	if (PQstatus(dbconn) != CONNECTION_OK) {
		warnx("%s: Connection to database failed: %s", __func__, PQerrorMessage(dbconn));
		PQfinish(dbconn);
		return (-1);
	} else
		warnx("DAO connected");

	dao_prepare_statements();

	return (0);
}

void
dao_fini()
{
	PQfinish(dbconn);
	dbconn = NULL;
}

void
dao_reset_node_state()
{
	PGresult *result;

	result = PQexec(dbconn, "UPDATE node SET status = 0 WHERE status = 1;");
	check_result_status(result);
}

int
dao_client_create(char *email, char *password, char *apikey)
{
	PGresult	*result = NULL;
	int		 paramLengths[3];
	const char	*paramValues[3];

	if (email == NULL || password == NULL || apikey == NULL) {
		warnx("invalid NULL parameter");
		return (-1);
	}

	paramValues[0] = email;
	paramValues[1] = password;
	paramValues[2] = apikey;

	paramLengths[0] = strlen(email);
	paramLengths[1] = strlen(password);
	paramLengths[2] = strlen(apikey);

	result = PQexecPrepared(dbconn, "dao_client_create", 3, paramValues, paramLengths, NULL, 0);

	if (check_result_status(result) == -1) {
		PQclear(result);
		return (-1);
	}

	PQclear(result);

	return (0);
}

int
dao_client_activate(char *apikey)
{
	PGresult	*result = NULL;
	int		 paramLengths[1];
	const char	*paramValues[1];

	if (apikey == NULL) {
		warnx("invalid NULL parameter");
		return (-1);
	}

	paramValues[0] = apikey;
	paramLengths[0] = strlen(apikey);

	result = PQexecPrepared(dbconn, "dao_client_activate", 1, paramValues, paramLengths, NULL, 0);

	if (check_result_status(result) == -1) {
		PQclear(result);
		return (-1);
	}

	/* if no row is updated, return an error */
	if (strcmp(PQcmdTuples(result), "0") == 0) {
		PQclear(result);
		return (-1);
	}

	PQclear(result);

	return (0);
}

int
dao_client_update_apikey(char *apikey, char *new_apikey)
{
	PGresult	*result = NULL;
	int		 paramLengths[2];
	const char	*paramValues[2];

	if (apikey == NULL || new_apikey == NULL) {
		warnx("invalid NULL parameter");
		return (-1);
	}

	paramValues[0] = apikey;
	paramValues[1] = new_apikey;

	paramLengths[0] = strlen(apikey);
	paramLengths[1] = strlen(new_apikey);

	result = PQexecPrepared(dbconn, "dao_client_update_apikey", 2, paramValues, paramLengths, NULL, 0);

	if (check_result_status(result) == -1) {
		PQclear(result);
		return (-1);
	}

	PQclear(result);

	return (0);
}

int
dao_client_update_apikey2(char *email, char *password, char *apikey)
{
	PGresult	*result = NULL;
	int		 paramLengths[3];
	const char	*paramValues[3];

	if (email == NULL || password == NULL || apikey == NULL) {
		warnx("invalid NULL parameter");
		return (-1);
	}

	paramValues[0] = email;
	paramValues[1] = password;
	paramValues[2] = apikey;

	paramLengths[0] = strlen(email);
	paramLengths[1] = strlen(password);
	paramLengths[2] = strlen(apikey);

	result = PQexecPrepared(dbconn, "dao_client_update_apikey2", 3, paramValues, paramLengths, NULL, 0);

	if (check_result_status(result) == -1) {
		PQclear(result);
		return (-1);
	}

	if (strcmp(PQcmdTuples(result), "0") == 0) {
		PQclear(result);
		return (-1);
	}

	PQclear(result);

	return (0);
}

int
dao_client_update_password(char *email, char *resetkey, char *password)
{
	PGresult	*result = NULL;
	int		 paramLengths[3];
	const char	*paramValues[3];

	if (email == NULL || resetkey == NULL || password == NULL) {
		warnx("invalid NULL parameter");
		return (-1);
	}

	paramValues[0] = email;
	paramValues[1] = resetkey;
	paramValues[2] = password;

	paramLengths[0] = strlen(email);
	paramLengths[1] = strlen(resetkey);
	paramLengths[2] = strlen(password);

	result = PQexecPrepared(dbconn, "dao_client_update_password", 3, paramValues, paramLengths, NULL, 1);

	if (check_result_status(result) == -1) {
		PQclear(result);
		return (-1);
	}

	if (strcmp(PQcmdTuples(result), "0") == 0) {
		PQclear(result);
		return (-1);
	}

	PQclear(result);

	return (0);
}

int
dao_client_update_resetkey(char *email, char *resetkey)
{
	PGresult	*result = NULL;
	const char	*paramValues[2];
	int		 paramLengths[2];

	if (email == NULL || resetkey == NULL) {
		warnx("invalid NULL parameter");
		return (-1);
	}

	paramValues[0] = email;
	paramValues[1] = resetkey;

	paramLengths[0] = strlen(email);
	paramLengths[1] = strlen(resetkey);

	result = PQexecPrepared(dbconn, "dao_client_update_resetkey", 2, paramValues, paramLengths, NULL, 0);

	if (check_result_status(result) == -1) {
		PQclear(result);
		return (-1);
	}

	if (strcmp(PQcmdTuples(result), "0") == 0) {
		PQclear(result);
		return (-1);
	}

	PQclear(result);

	return (0);
}

int 
dao_client_get_id(char **id, const char *apikey)
{
	PGresult	*result = NULL;
	int		 paramLengths[1];
	int		 tuples;
	int		 fields;
	const char	*paramValues[1];

	if (apikey == NULL) {
		warnx("invalid NULL parameter");
		return (-1);
	}
	paramValues[0] = apikey;
	paramLengths[0] = strlen(apikey);

	result = PQexecPrepared(dbconn, "dao_client_get_id", 1, paramValues, paramLengths, NULL, 0);

	if (check_result_status(result) == -1) {
		PQclear(result);
		return (-1);
	}

	tuples = PQntuples(result);
	fields = PQnfields(result);

	if (tuples > 0 && fields > 0) 
		*id = strdup(PQgetvalue(result, 0, 0));

	PQclear(result);

	return 0;
}


int
dao_network_create(char *client_id,
	char *uid,
	char *description,
	char *subnet,
	char *netmask,
	char *embassy_certificate,
	char *embassy_privatekey,
	char *embassy_serial,
	char *passport_certificate,
	char *passport_privatekey,
	const unsigned char *ippool,
	size_t pool_size)
{
	PGresult	*result;
	size_t		 ippool_str_len;
	int		 paramLengths[11];
	const char	*paramValues[11];
	unsigned char	*ippool_str;

	if (uid == NULL || client_id == NULL || description == NULL ||
	    subnet == NULL || netmask == NULL || embassy_certificate == NULL ||
	    embassy_privatekey == NULL || embassy_serial == NULL ||
	    passport_certificate == NULL || passport_privatekey == NULL) {
		warnx("invalid NULL parameter");
		return (-1);
	}

	ippool_str = PQescapeByteaConn(dbconn, ippool, pool_size, &ippool_str_len);

	paramValues[0] = client_id;
	paramValues[1] = uid;
	paramValues[2] = description;
	paramValues[3] = subnet;
	paramValues[4] = netmask;
	paramValues[5] = embassy_certificate;
	paramValues[6] = embassy_privatekey;
	paramValues[7] = embassy_serial;
	paramValues[8] = passport_certificate;
	paramValues[9] = passport_privatekey;
	paramValues[10] = (char *)ippool_str;

	paramLengths[0] = strlen(client_id);
	paramLengths[1] = strlen(uid);
	paramLengths[2] = strlen(description);
	paramLengths[3] = strlen(subnet);
	paramLengths[4] = strlen(netmask);
	paramLengths[5] = strlen(embassy_certificate);
	paramLengths[6] = strlen(embassy_privatekey);
	paramLengths[7] = strlen(embassy_serial);
	paramLengths[8] = strlen(passport_certificate);
	paramLengths[9] = strlen(passport_privatekey);
	paramLengths[10] = ippool_str_len;

	result = PQexecPrepared(dbconn, "dao_network_create", 11, paramValues, paramLengths, NULL, 0);

	PQfreemem(ippool_str);

	if (check_result_status(result) == -1) {
		PQclear(result);
		return (-1);
	}

	PQclear(result);

	return (0);
}

int
dao_network_delete(const char *description, const char *apikey)
{
	PGresult	*result;
	int		 paramLengths[2];
	const char	*paramValues[2];

	if (description == NULL || apikey == NULL) {
		warnx("invalid parameter");
		return (-1);
	}

	paramValues[0] = description;
	paramValues[1] = apikey;

	paramLengths[0] = strlen(description);
	paramLengths[1] = strlen(apikey);

	result = PQexecPrepared(dbconn, "dao_network_delete", 2, paramValues, paramLengths, NULL, 0);

	if (check_result_status(result) == -1) {
		PQclear(result);
		return (-1);
	}

	/* if no row is deleted, return an error */
	if (strcmp(PQcmdTuples(result), "0") == 0) {
		PQclear(result);
		return (-1);
	}

	PQclear(result);

	return (0);
}

int
dao_network_list(const char *apikey,
	    int (*cb)(const char *, const char *, void *),
	    void *arg)
{
	PGresult	*result;
	int		 paramLengths[1];
	int		 tuples;
	int		 i;
	const char	*paramValues[1];

	if (apikey == NULL) {
		warnx("invalid NULL parameter");
		return (-1);
	}

	paramValues[0] = apikey;
	paramLengths[0] = strlen(apikey);

	result = PQexecPrepared(dbconn, "dao_network_list", 1, paramValues, paramLengths, NULL, 0);

	if (check_result_status(result) == -1) {
		PQclear(result);
		return (-1);
	}

	tuples = PQntuples(result);

	for (i = 0; i < tuples; i++)
		cb(PQgetvalue(result, i, 0), PQgetvalue(result, i, 1), arg);

	PQclear(result);

	return (0);
}

int
dao_network_get_embassy(
    const char *network_uid,
    char **cert,
    char **pvkey,
    char **serial)
{
	PGresult	*result;
	int		 paramLengths[1];
	int		 tuples;
	int		 fields;
	const char	*paramValues[1];

	if (network_uid == NULL) {
		warnx("invalid NULL parameter");
		return (-1);
	}

	paramValues[0] = network_uid;
	paramLengths[0] = strlen(network_uid);

	result = PQexecPrepared(dbconn, "dao_network_get_embassy", 1, paramValues, paramLengths, NULL, 0);

	if (check_result_status(result) == -1) {
		PQclear(result);
		return (-1);
	}

	if ((tuples = PQntuples(result)) > 0 &&
	    (fields = PQnfields(result)) > 0) {
		*cert = strdup(PQgetvalue(result, 0, 0));
		*pvkey = strdup(PQgetvalue(result, 0, 1));
		*serial = strdup(PQgetvalue(result, 0, 2));
	} else {
		PQclear(result);
		return (-1);
	}

	PQclear(result);

	return (0);
}

int
dao_network_get_ippool(
    const char	*description,
    char	**uid,
    char	**subnet,
    char	**netmask,
    uint8_t	**ippool)
{
	PGresult	*result;
	size_t		 ippool_size;
	int		 paramLengths[1];
	int		 tuples;
	int		 fields;
	uint8_t		*ippool_ptr;
	const char	*paramValues[1];

	paramValues[0] = description;
	paramLengths[0] = strlen(description);

	result = PQexecPrepared(dbconn, "dao_network_get_ippool", 1, paramValues, paramLengths, NULL, 0);

	if (check_result_status(result) == -1) {
		PQclear(result);
		return (-1);
	}

	if ((tuples = PQntuples(result)) > 0 &&
	    (fields = PQnfields(result)) == 4) {
		*uid = strdup(PQgetvalue(result, 0, 0));
		*subnet = strdup(PQgetvalue(result, 0, 1));
		*netmask = strdup(PQgetvalue(result, 0, 2));

		ippool_ptr = (uint8_t *)PQgetvalue(result, 0, 3);
		ippool_size = PQgetlength(result, 0, 3);
		*ippool = PQunescapeBytea(ippool_ptr, &ippool_size);
	} else {
		PQclear(result);
		return (-1);
	}

	PQclear(result);

	return (0);
}

int
dao_network_update_ippool(const char *network_uuid,
    uint8_t *ippool, size_t pool_size)
{
	PGresult	*result = NULL;
	size_t		 ippool_str_len;
	int		 paramLengths[2];
	const char	*paramValues[2];
	uint8_t		*ippool_str;

	if ((ippool_str = PQescapeByteaConn(dbconn, ippool, pool_size,
	    &ippool_str_len)) == NULL) {
		warnx("%s: PQescapeByteaConn", __func__);
			return (-1);
	}

	paramValues[0] = network_uuid;
	paramLengths[0] = strlen(network_uuid);

	paramValues[1] = (char *)ippool_str;
	paramLengths[1] = ippool_str_len;

	result = PQexecPrepared(dbconn, "dao_network_update_ippool", 2, paramValues, paramLengths, NULL, 1);

	PQfreemem(ippool_str);

	if (check_result_status(result) == -1) {
		PQclear(result);
		return (-1);
	}

	PQclear(result);

	return (0);
}

int
dao_network_update_serial(const char *network_uuid, const char *serial)
{
	PGresult	*result = NULL;
	int		 paramLengths[2];
	const char	*paramValues[2];

	paramValues[0] = network_uuid;
	paramLengths[0] = strlen(network_uuid);

	paramValues[1] = serial;
	paramLengths[1] = strlen(serial);

	result = PQexecPrepared(dbconn, "dao_network_update_serial", 2, paramValues, paramLengths, NULL, 1);

	if (check_result_status(result) == -1) {
		PQclear(result);
		return (-1);
	}

	PQclear(result);

	return (0);
}


int
dao_node_create(const char *network_uid, const char *uid, const char *provkey,
	    const char *description, const char *ipaddress)
{
	PGresult	*result;
	int		 paramLengths[5];
	const char	*paramValues[5];

	if (network_uid == NULL || uid == NULL || provkey == NULL ||
	    description == NULL || ipaddress == NULL) {
		warnx("invalid NULL parameter");
		return (-1);
	}

	paramValues[0] = network_uid;
	paramValues[1] = uid;
	paramValues[2] = provkey;
	paramValues[3] = description;
	paramValues[4] = ipaddress;

	paramLengths[0] = strlen(network_uid);
	paramLengths[1] = strlen(uid);
	paramLengths[2] = strlen(provkey);
	paramLengths[3] = strlen(description);
	paramLengths[4] = strlen(ipaddress);

	result = PQexecPrepared(dbconn, "dao_node_create", 5, paramValues, paramLengths, NULL, 0);

	if (check_result_status(result) == -1) {
		PQclear(result);
		return (-1);
	}

	PQclear(result);

	return (0);
}

int
dao_node_delete(const char *uid, const char *apikey)
{
	const char *paramValues[2];
	int paramLengths[2];
	PGresult *result;

	if (uid == NULL || apikey == NULL) {
		warnx("invalid NULL parameter");
		return (-1);
	}

	paramValues[0] = uid;
	paramValues[1] = apikey;

	paramLengths[0] = strlen(uid);
	paramLengths[1] = strlen(apikey);

	result = PQexecPrepared(dbconn, "dao_node_delete", 2, paramValues, paramLengths, NULL, 0);

	if (check_result_status(result) == -1) {
		PQclear(result);
		return (-1);
	}

	/* if no row is deleted, return an error */
	if (strcmp(PQcmdTuples(result), "0") == 0) {
		PQclear(result);
		return (-1);
	}

	PQclear(result);

	return (0);
}

int
dao_node_netinfo(const char *description, const char *apikey,
    char **ipaddr, char **network_uid, char **subnet,
    char **netmask, uint8_t **ippool_bin)
{
	PGresult	*result;
	size_t		 ippool_size;
	int		 paramLengths[2];
	uint8_t		*ippool_ptr;
	const char	*paramValues[2];

	paramValues[0] = description;
	paramValues[1] = apikey;

	paramLengths[0] = strlen(description);
	paramLengths[1] = strlen(apikey);

	result = PQexecPrepared(dbconn, "dao_node_netinfo", 2, paramValues, paramLengths, NULL, 0);
	if (check_result_status(result) == -1) {
		PQclear(result);
		warnx("%s: PQexecPrepared", __func__);
		return (-1);
	}

	if (PQntuples(result) > 0 && PQnfields(result) == 5) {
		*ipaddr = strdup(PQgetvalue(result, 0, 0));
		*network_uid = strdup(PQgetvalue(result, 0, 1));
		*subnet = strdup(PQgetvalue(result, 0, 2));
		*netmask = strdup(PQgetvalue(result, 0, 3));

		ippool_ptr = (uint8_t*)PQgetvalue(result, 0, 4);
		ippool_size = PQgetlength(result, 0, 4);
		*ippool_bin = PQunescapeBytea(ippool_ptr, &ippool_size);
	} else {
		PQclear(result);
		warnx("%s: PQntuples PQnfields", __func__);
		return (-1);
	}

	PQclear(result);

	return (0);
}

int
dao_node_list(const char *network_uid, const char *apikey,
	    int (*cb)(const char *, const char *, const char *, const char *, const char *, void *),
	    void *arg)
{
	PGresult	*result;
	int		 paramLengths[2];
	int		 tuples;
	int		 i;
	const char 	*paramValues[2];

	if (network_uid == NULL) {
		warnx("invalid NULL parameter");
		return (-1);
	}

	paramValues[0] = network_uid;
	paramValues[1] = apikey;

	paramLengths[0] = strlen(network_uid);
	paramLengths[1] = strlen(apikey);

	result = PQexecPrepared(dbconn, "dao_node_list", 2, paramValues, paramLengths, NULL, 0);

	if (check_result_status(result) == -1) {
		PQclear(result);
		return (-1);
	}

	tuples = PQntuples(result);

	for (i = 0; i < tuples; i++) {
		cb(PQgetvalue(result, i, 0),
		    PQgetvalue(result, i, 1),
		    PQgetvalue(result, i, 2),
		    PQgetvalue(result, i, 3),
		    PQgetvalue(result, i, 4), arg);
	}

	PQclear(result);

	return (0);
}

int
dao_node_delete_provkey(const char *network_uid, const char *node_uid, const char *provkey)
{
	PGresult	*result = NULL;
	int		 paramLengths[3];
	const char	*paramValues[3];

	paramValues[0] = network_uid;
	paramValues[1] = node_uid;
	paramValues[2] = provkey;

	paramLengths[0] = strlen(network_uid);
	paramLengths[1] = strlen(node_uid);
	paramLengths[2] = strlen(provkey);

	result = PQexecPrepared(dbconn, "dao_node_delete_provkey", 3, paramValues, paramLengths, NULL, 0);

	if (check_result_status(result) == -1) {
		PQclear(result);
		return (-1);
	}

	/* if no row is updated, return an error */
	if (strcmp(PQcmdTuples(result), "0") == 0) {
		PQclear(result);
		return (-1);
	}

	PQclear(result);

	return (0);
}

int
dao_node_listall(void *data,
    int (*cb)(void *, int, const char *, const char *, const char *, const char *))
{
	PGresult	*result;
	int		 i;
	int		 tuples;
	int		 ret;

	result = PQexecPrepared(dbconn, "dao_node_listall", 0, NULL, NULL, NULL, 0);

	if (check_result_status(result) == -1) {
		PQclear(result);
		goto error;
	}

	for (tuples = PQntuples(result), i = 0; i < tuples; i++) {
		if ((ret = cb(data, tuples - i - 1,
			PQgetvalue(result, i, 0),
			PQgetvalue(result, i, 1),
			PQgetvalue(result, i, 2),
			PQgetvalue(result, i, 3))) < 0)
				goto error;
	}

	PQclear(result);
	return (0);

error:
	PQclear(result);
	return (-1);
}


int
dao_switch_network_list(void *data,
    int (*cb)(void *, int , const char *, const char *, const char *, const char *))
{
	int		 i;
	int		 ret;
	int		 tuples;
	PGresult	*result;

	result = PQexecPrepared(dbconn, "dao_switch_network_list", 0, NULL, NULL, NULL, 0);

	if (check_result_status(result) == -1) {
		PQclear(result);
		return (-1);
	}

	for (tuples = PQntuples(result), i = 0; i < tuples; i++) {
		if ((ret = cb(data, tuples - i - 1,
		    PQgetvalue(result, i, 0),
		    PQgetvalue(result, i, 1),
		    PQgetvalue(result, i, 2),
		    PQgetvalue(result, i, 3))) < 0)
			goto out;
	}

out:
	PQclear(result);
	return (0);
}















#if 0
int dao_fetch_client_id(char **client_id, char *email, char *password)
{
	const char *paramValues[2];
	int paramLengths[2];
	int tuples;
	int fields;
	PGresult *result = NULL;

	if (!client_id || !email || !password) {
		warnx("invalid NULL parameter");
		return -1;
	}

	paramValues[0] = email;
	paramValues[1] = password;

	paramLengths[0] = strlen(email);
	paramLengths[1] = strlen(password);

	result = PQexecPrepared(dbconn, "dao_fetch_client_id", 2, paramValues, paramLengths, NULL, 0);

	if (!result) {
		warnx("PQexec command failed: %s", PQerrorMessage(dbconn));
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

	warnx("Tuples %d", tuples);
	warnx("Fields %d", fields);

	PQclear(result);

	return 0;
}
int dao_update_node_status(char *network_uuid, char *uuid, char *status, char *ipsrc)
{
	const char *paramValues[4];
	int paramLengths[4];
	PGresult *result = NULL;

	if (!network_uuid || !uuid || !status || !ipsrc) {
		warnx("invalid parameter");
		return -1;
	}

	paramValues[0] = network_uuid;
	paramValues[1] = uuid;
	paramValues[2] = status;
	paramValues[3] = ipsrc;

	paramLengths[0] = strlen(network_uuid);
	paramLengths[1] = strlen(uuid);
	paramLengths[2] = strlen(status);
	paramLengths[3] = strlen(ipsrc);

	result = PQexecPrepared(dbconn, "dao_update_node_status", 4, paramValues, paramLengths, NULL, 1);

	if (!result) {
		warnx("PQexec command failed: %s", PQerrorMessage(dbconn));
		return -1;
	}

	if (check_result_status(result) == -1) {
		PQclear(result);
		return -1;
	}

	PQclear(result);

	return 0;
}


int dao_del_node_by_network_uid(char *network_uuid)
{
	const char *paramValues[1];
	int paramLengths[1];
	PGresult *result;

	if (!network_uuid) {
		warnx("invalid parameter");
		return -1;
	}

	paramValues[0] = network_uuid;
	paramLengths[0] = strlen(network_uuid);

	result = PQexecPrepared(dbconn, "dao_del_node_by_network_uid", 1, paramValues, paramLengths, NULL, 0);

	if (!result) {
		warnx("PQexec command failed: %s", PQerrorMessage(dbconn));
		PQclear(result);
		return -1;
	}

	PQclear(result);

	return 0;
}

int dao_fetch_network_ippool(char *network_uuid, unsigned char **ippool)
{
	const char *paramValues[1];
	int paramLengths[1];
	unsigned char *ippool_ptr;
	size_t ippool_size;
	PGresult *result;

	if (!network_uuid) {
		warnx("invalid NULL parameter");
		return -1;
	}

	paramValues[0] = network_uuid;
	paramLengths[0] = strlen(network_uuid);

	result = PQexecPrepared(dbconn, "dao_fetch_network_ippool", 1, paramValues, paramLengths, NULL, 0);

	if (!result) {
		warnx("PQexec command failed: %s", PQerrorMessage(dbconn));
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

int dao_fetch_network_id(char **network_id, char *client_id, char *uuid)
{
	const char *paramValues[2];
	int paramLengths[2];
	PGresult *result;

	if (!client_id || !uuid) {
		warnx("invalid NULL parameter");
		return -1;
	}

	paramValues[0] = client_id;
	paramValues[1] = uuid;

	paramLengths[0] = strlen(client_id);
	paramLengths[0] = strlen(uuid);

	result = PQexecPrepared(dbconn, "dao_fetch_network_id", 2, paramValues, paramLengths, NULL, 0);

	if (!result) {
		warnx("PQexec command failed: %s", PQerrorMessage(dbconn));
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
		*network_id = strdup(PQgetvalue(result, 0, 0));
	} else {
		PQclear(result);
		return -1;
	}

	PQclear(result);

	return 0;
}

int dao_fetch_network_embassy(char *uuid,
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

	if (!uuid || !certificate || !privatekey || !serial) {
		warnx("invalid NULL parameter");
		return -1;
	}

	paramValues[0] = uuid;
	paramLengths[0] = strlen(uuid);

	result = PQexecPrepared(dbconn, "dao_fetch_network_embassy", 1, paramValues, paramLengths, NULL, 0);

	if (!result) {
		warnx("PQexec command failed: %s", PQerrorMessage(dbconn));
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

int dao_update_network_ippool(char *network_uuid, unsigned char *ippool, int pool_size)
{
	const char *paramValues[2];
	int paramLengths[2];
	PGresult *result = NULL;
	unsigned char *ippool_str;
	size_t ippool_str_len;

	if (!network_uuid || !ippool) {
		warnx("invalid NULL parameter");
		return -1;
	}

	ippool_str = PQescapeByteaConn(dbconn, ippool, pool_size, &ippool_str_len);

	paramValues[0] = network_uuid;
	paramLengths[0] = strlen(network_uuid);

	paramValues[1] = (char *)ippool_str;
	paramLengths[1] = ippool_str_len;

	result = PQexecPrepared(dbconn, "dao_update_network_ippool", 2, paramValues, paramLengths, NULL, 1);

	PQfreemem(ippool_str);

	if (!result) {
		warnx("PQexec command failed: %s", PQerrorMessage(dbconn));
		return -1;
	}

	if (check_result_status(result) == -1) {
		PQclear(result);
		return -1;
	}

	PQclear(result);

	return 0;
}

int dao_update_embassy_serial(char *network_uuid, char *serial)
{
	const char *paramValues[2];
	int paramLengths[2];
	PGresult *result = NULL;

	if (!network_uuid || !serial) {
		warnx("invalid NULL parameter");
		return -1;
	}

	paramValues[0] = network_uuid;
	paramLengths[0] = strlen(network_uuid);

	paramValues[1] = serial;
	paramLengths[1] = strlen(serial);

	result = PQexecPrepared(dbconn, "dao_update_embassy_serial", 2, paramValues, paramLengths, NULL, 1);

	if (!result) {
		warnx("PQexec command failed: %s", PQerrorMessage(dbconn));
		return -1;
	}

	if (check_result_status(result) == -1) {
		PQclear(result);
		return -1;
	}

	PQclear(result);

	return 0;
}



int dao_fetch_node_sequence(uint32_t *network_id_list, uint32_t list_size, void *data, void (*cb_data_handler)(void *data, int remaining,
								char *uuid, char *networkId))
{
	PGresult *result;

	int cursor = 0;
	int total_size = 0;
	char *fetch_req = NULL;
	uint32_t i = 0;

	total_size = (5*list_size) + strlen("SELECT node.uuid, node.network_id FROM node WHERE node.network_id IN ();");
	fetch_req = calloc(1, total_size);
	cursor = snprintf(fetch_req, total_size, "SELECT node.uuid, node.network_id FROM node WHERE node.network_id IN (%d", network_id_list[0]);
	for (i = 1; i < list_size; i++) {
		cursor += snprintf(fetch_req+cursor, total_size-cursor, ",%d", network_id_list[i]);
	}
	snprintf(fetch_req+cursor, total_size-cursor, ");");

	result = PQexec(dbconn, fetch_req);
	if (!result) {
		warnx("PQexec command failed: %s", PQerrorMessage(dbconn));
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

int dao_fetch_node_uuid_networkuuid(void *arg, int (*cb_data_handler)(void *, int, char *, char *))
{
	int		 i;
	int		 ret;
	int		 tuples;
	PGresult	*result;

	if ((result = PQexecPrepared(dbconn, "dao_fetch_node_uuid_networkuuid", 0, NULL, NULL, NULL, 0)) == NULL) {
		warnx("PQexec command failed: %s\n", PQerrorMessage(dbconn));
		return -1;
	}

	if (check_result_status(result) == -1) {
		PQclear(result);
		return -1;
	}

	tuples = PQntuples(result);
	for (i = 0; i < tuples; i++) {
		ret = cb_data_handler(arg, tuples - i - 1,
			PQgetvalue(result, i, 0),
			PQgetvalue(result, i, 1));

		if (ret == -1)
			goto out;
	}

	PQclear(result);
	return 0;

out:
	PQclear(result);
	return -1;
}

int dao_fetch_node_ip(char *network_uuid, char *uuid, char **ipaddress)
{
	const char *paramValues[2];
	int paramLengths[2];
	PGresult *result;

	if (!network_uuid || !uuid) {
		warnx("invalid NULL parameter");
		return -1;
	}

	paramValues[0] = network_uuid;
	paramLengths[0] = strlen(network_uuid);

	paramValues[1] = uuid;
	paramLengths[1] = strlen(uuid);

	result = PQexecPrepared(dbconn, "dao_fetch_node_ip", 2, paramValues, paramLengths, NULL, 0);
	if (!result) {
		warnx("PQexec command failed: %s", PQerrorMessage(dbconn));
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

int dao_fetch_node_from_provkey(char *provkey,
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
						"network.embassy_certificate as trustedcert "
					"FROM	node, network "
					"WHERE	provkey = '%s' "
					"AND	node.network_uid = network.uid;",
					provkey);

	result = PQexec(dbconn, fetch_req);

	if (!result) {
		warnx("PQexec command failed: %s", PQerrorMessage(dbconn));
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


int dao_fetch_network_by_client_id_desc(char *client_id, char *description,
					void *data, int (*cb_data_handler)(void *data,
					char *id,
					char *description,
					char *client_id,
					char *subnet,
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
		warnx("invalid NULL parameter");
		return -1;
	}

	paramValues[0] = client_id;
	paramValues[1] = description;
	paramLengths[0] = strlen(client_id);
	paramLengths[1] = strlen(description);

	result = PQexecPrepared(dbconn, "dao_fetch_network_by_client_id_desc", 2, paramValues, paramLengths, NULL, 0);

	if (!result) {
		warnx("PQexec command failed: %s", PQerrorMessage(dbconn));
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
#endif
