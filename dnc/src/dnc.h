#ifndef DNC_DNC_H
#define DNC_DNC_H

int dnc_init(char *server_address, char *server_port, char *prov_code,
		char *certificate, char *privatekey, char *trusted_authority);

#endif /* DNC_DNC_H */
