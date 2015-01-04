/*
 * NetVirt - Network Virtualization Platform
 * Copyright (C) 2009-2014
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

#include "pki.h"

int certs_bootstrap()
{
	uint32_t expiration_delay;
	long size;
	int ret = 0;
	char *cert_ptr, *pvkey_ptr;

	expiration_delay = pki_expiration_delay(10);

	/* switch (nvs) <--> controller (nvc) <--> application (nvp) */
	digital_id_t *nvs_digital_id, *nvc_digital_id, *nvp_digital_id;

	nvs_digital_id = pki_digital_id("netvirt-switch", "", "", "", "admin@netvirt.org", "www.netvirt.org");
	nvc_digital_id = pki_digital_id("netvirt-ctrler", "", "", "", "admin@netvirt.org", "www.vetvirt.org");
	nvp_digital_id = pki_digital_id("netvirt-app", "", "", "", "admin@netvirt.org", "www.netvirt.org");

	embassy_t *nvc_embassy;
	nvc_embassy = pki_embassy_new(nvc_digital_id, expiration_delay);

	passport_t *nvs_passport;
	nvs_passport = pki_embassy_deliver_passport(nvc_embassy, nvs_digital_id, expiration_delay);

	passport_t *nvp_passport;
	nvp_passport = pki_embassy_deliver_passport(nvc_embassy, nvp_digital_id, expiration_delay);

	pki_write_certificate_in_mem(nvc_embassy->certificate, &cert_ptr, &size);
	pki_write_privatekey_in_mem(nvc_embassy->keyring, &pvkey_ptr, &size);

	ret = pki_write_certificate(nvc_embassy->certificate, "/etc/netvirt/certs/netvirt-ctrler-cert.pem");
	if (ret == -1) {
		fprintf(stderr, "can't write: /etc/netvirt/certs/netvirt-ctrler-cert.pem\n");
		goto out;
	} else {
		fprintf(stdout, "/etc/netvirt/certs/netvirt-ctrler-cert.pem... done\n");
	}
	ret = pki_write_privatekey(nvc_embassy->keyring, "/etc/netvirt/certs/netvirt-ctrler-privkey.pem");
	if (ret == -1) {
		fprintf(stderr, "can't write: /etc/netvirt/certs/netvirt-ctrler-privkey.pem\n");
		goto out;
	} else {
		fprintf(stdout, "/etc/netvirt/certs/netvirt-ctrler-privkey.pem... done\n");
	}

	ret = pki_write_certificate(nvs_passport->certificate, "/etc/netvirt/certs/netvirt-switch-cert.pem");
	if (ret == -1) {
		fprintf(stderr, "can't write: /etc/netvirt/certs/netvirt-switch-cert.pem\n");
		goto out;
	} else {
		fprintf(stdout, "/etc/netvirt/certs/netvirt-switch-cert.pem... done\n");
	}
	ret = pki_write_privatekey(nvs_passport->keyring, "/etc/netvirt/certs/netvirt-switch-privkey.pem");
	if (ret == -1) {
		fprintf(stderr, "can't write: /etc/netvirt/certs/netvirt-switch-privkey.pem\n");
		goto out;
	} else {
		fprintf(stdout, "/etc/netvirt/certs/netvirt-switch-privkey.pem... done\n");
	}

	ret = pki_write_certificate(nvp_passport->certificate, "/etc/netvirt/certs/netvirt-app-cert.pem");
	if (ret == -1) {
		fprintf(stderr, "can't write: /etc/netvirt/certs/netvirt-app-cert.pem\n");
		goto out;
	} else {
		fprintf(stdout, "/etc/netvirt/certs/netvirt-app-cert.pem... done\n");
	}
	ret = pki_write_privatekey(nvp_passport->keyring, "/etc/netvirt/certs/netvirt-app-privkey.pem");
	if (ret == -1) {
		fprintf(stderr, "/etc/netvirt/certs/netvirt-app-privkey.pem\n");
		goto out;
	} else {
		fprintf(stdout, "/etc/netvirt/certs/netvirt-app-privkey.pem... done\n");
	}
out:
	pki_embassy_free(nvc_embassy);
	pki_passport_free(nvs_passport);
	pki_passport_free(nvp_passport);

	return 0;
}
