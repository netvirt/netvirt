#ifndef DND_DSC_H
#define DND_DSC_H

#include <dnds/dnds.h>

int transmit_peerconnectinfo(e_ConnectState state, char *ipAddress, char *certName);
int dsc_init(char *address, char *port, char *certificate, char *priatekey, char *trusted_authority);

#endif /* DND_DSC_H */
