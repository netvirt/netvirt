#ifndef DNC_REQUEST_H
#define DNC_REQUEST_H

#include <stdint.h>
#include <dnds/net.h>

void request_p2p(netc_t *netc, uint8_t *mac_src, uint8_t *mac_dst);

#endif /* DNC_REQUEST_H */
