#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <stdio.h>

#include <dnds/dnds.h>
#include <dnds/journal.h>
#include <dnds/netbus.h>
#include <dnds/pki.h>
#include <dnds/xsched.h>
#include <dnds/net.h>

netc_t *netc;

void client_authenticate(netc_t *netc)
{
	size_t nbyte;

	// Building an AuthRequest

	DNDSMessage_t *msg;

	DNDSMessage_new(&msg);
	DNDSMessage_set_channel(msg, 10);
	DNDSMessage_set_pdu(msg, pdu_PR_dsm);

	DSMessage_set_seqNumber(msg, 1);
	DSMessage_set_ackNumber(msg, 0);
	DSMessage_set_operation(msg, dsop_PR_authRequest);

	AuthRequest_set_certName(msg, "nib@2", 5);

	nbyte = net_send_msg(netc, msg);

	if (nbyte == -1) {
		JOURNAL_NOTICE("client]> malformed message\n", nbyte);
		return;
	}

	JOURNAL_NOTICE("client]> sent %i bytes\n", nbyte);

	return;
}

void on_secure(netc_t *netc)
{
	printf("on secure!\n");
	client_authenticate(netc);
}

void on_input(netc_t *netc)
{
	DNDSMessage_t *msg;
	mbuf_t **mbuf_itr;

	mbuf_itr = &netc->queue_msg;

	while (*mbuf_itr != NULL) {

		msg = (DNDSMessage_t *)(*mbuf_itr)->ext_buf;
		DNDSMessage_printf(msg);
		AuthResponse_printf(msg);

		mbuf_del(mbuf_itr, *mbuf_itr);
	}

	return;
}

void on_disconnect(netc_t *netc)
{
	printf("on_disconnect\n");
	// XXX reconnect
}

int main()
{

	if (event_init()) {
		JOURNAL_ERR("dsc]> event initialisation failed :: %s:%i\n", __FILE__, __LINE__);
		exit(EXIT_ERR);
	}

	if (scheduler_init()) {
		JOURNAL_ERR("dsc]> scheduler initialisation failed :: %s:%i\n", __FILE__, __LINE__);
		exit(EXIT_ERR);
	}

	if (netbus_init()) {
		JOURNAL_ERR("dsc]> netbus initialisation failed :: %s:%i\n", __FILE__, __LINE__);
		exit(EXIT_ERR);
	}

	if (krypt_init()) {
		JOURNAL_ERR("dsc]> krypt initialisation failed :: %s:%i\n", __FILE__, __LINE__);
		exit(EXIT_ERR);
	}

	passport_t *dsc_passport;
	dsc_passport = pki_passport_load_from_file("/usr/local/etc/dnds/dsc/dsc_cert.pem",
					       "/usr/local/etc/dnds/dsc/dsc_privkey.pem",
					       "/usr/local/etc/dnds/dsc/dsd_cert.pem");

	netc = net_client("127.0.0.1", "9090", NET_PROTO_UDT, NET_SECURE_RSA, dsc_passport,
				on_disconnect, on_input, on_secure);
	if (netc == NULL) {
		JOURNAL_NOTICE("dsc]> connection failed :: %s:%i\n", __FILE__, __LINE__);
		exit(EXIT_ERR);
	}

	scheduler();
}
