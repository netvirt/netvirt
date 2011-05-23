// API Dynamic-Network-Directory-Service-Protocol-V1
// Copyright (C) Nicolas Bouliane - Mind4Networks, 2010

#include "dnds.h"

static int write_out(const void *buffer, size_t size, void *app_key)
{
	FILE *out_fp = app_key;
	size_t wrote;

	wrote = fwrite(buffer, 1, size, out_fp);

	return (wrote == size) ? 0 : -1;
}

DNDSMessage_t *decode()
{
	char buf[1024];

	DNDSMessage_t *msg = NULL;	// Type to Decode
	asn_dec_rval_t rval;
	FILE *fp;
	size_t size;
	char *filename = "dnds.ber";

	fp = fopen(filename, "rb");
	if (fp == NULL)
		exit(-1);

	size = fread(buf, 1, sizeof(buf), fp);
	fclose(fp);
	rval = ber_decode(0, &asn_DEF_DNDSMessage, (void **)&msg, buf, size);
	if (rval.code != RC_OK) {
		fprintf(stderr, "%s: broken dndsmessage encoding at byte %ld\n",
			filename, (long)rval.consumed);
			exit(-1);
	}

	int ret;
	char errbuf[128] = {0};
	size_t errlen = sizeof(errbuf);

	ret = asn_check_constraints(&asn_DEF_DNDSMessage, msg, errbuf, &errlen);
	printf("ret %i::%s\n", ret, errbuf);

	return msg;
}

void show_DNDS_ethernet()
{
	DNDSMessage_t *msg;
	msg = decode();
	DNDSMessage_printf(msg);
}

void test_DNDS_ethernet()
{
	/// Building an message ethernet frame ///

	DNDSMessage_t *msg;	// a DNDS Message

	DNDSMessage_new(&msg);
	DNDSMessage_set_channel(msg, 0);
	DNDSMessage_set_pdu(msg, pdu_PR_ethernet);	// ethernet frame

	uint8_t *frame = strdup("0110101010101");
	size_t frame_size = 13;

	DNDSMessage_set_ethernet(msg, frame, frame_size);

	/// Encoding part

	asn_enc_rval_t ec;	// Encoder return value
	FILE *fp = fopen("dnds.ber", "wb"); // BER output
	ec = der_encode(&asn_DEF_DNDSMessage, msg, write_out, fp);
	fclose(fp);

	xer_fprint(stdout, &asn_DEF_DNDSMessage, msg);

	DNDSMessage_del(msg);
}

void show_AddRequest()
{
	DNDSMessage_t *msg;

	msg = decode();
	DNDSMessage_printf(msg);
	DSMessage_printf(msg);
	AddRequest_printf(msg);

	DNDSObject_t *obj;
	AddRequest_get_object(msg, &obj);
	DNDSObject_printf(obj);
}

void test_AddRequest()
{
	/// Building a AddRequest ///

	DNDSMessage_t *msg;	// a DNDS Message
	DNDSObject_t *objUser;	// a DS Object

	DNDSMessage_new(&msg);
	DNDSMessage_set_channel(msg, 0);
	DNDSMessage_set_pdu(msg, pdu_PR_dsm);	// Directory Service Message

	DSMessage_set_seqNumber(msg, 4034);
	DSMessage_set_ackNumber(msg, 0);	// seq XOR ack
	DSMessage_set_operation(msg, dsop_PR_addRequest);

	AddRequest_set_objectType(msg, DNDSObject_PR_user, &objUser);

	User_set_id(objUser, 1);
	User_set_contextId(objUser, 1);
	User_set_name(objUser, "nicboul", 6);
	User_set_password(objUser, "pwdpwd", 6);
	User_set_firstname(objUser, "nicolas", 7);
	User_set_lastname(objUser, "bouliane", 8);
	User_set_email(objUser, "nicboul@gmail.com", 15);
	User_set_role(objUser, 0);
	User_set_status(objUser, 0);

	/// Encoding part

	asn_enc_rval_t ec;	// Encoder return value
	FILE *fp = fopen("dnds.ber", "wb"); // BER output
	ec = der_encode(&asn_DEF_DNDSMessage, msg, write_out, fp);
	fclose(fp);

	xer_fprint(stdout, &asn_DEF_DNDSMessage, msg);

	DNDSMessage_del(msg);
}

void show_AddResponse()
{
	DNDSMessage_t *msg;

	msg = decode();
	DNDSMessage_printf(msg);
	DSMessage_printf(msg);
	AddResponse_printf(msg);
}

void test_AddResponse()
{
	/// Building a AddResponse ///

	DNDSMessage_t *msg;	// a DNDS Message

	DNDSMessage_new(&msg);
	DNDSMessage_set_channel(msg, 0);
	DNDSMessage_set_pdu(msg, pdu_PR_dsm);	// Directory Service Message

	DSMessage_set_seqNumber(msg, 0);
	DSMessage_set_ackNumber(msg, 4034);
	DSMessage_set_operation(msg, dsop_PR_addResponse);

	AddResponse_set_result(msg, DNDSResult_success);

	/// Encoding part

	asn_enc_rval_t ec;	// Encoder return value
	FILE *fp = fopen("dnds.ber", "wb"); // BER output
	ec = der_encode(&asn_DEF_DNDSMessage, msg, write_out, fp);
	fclose(fp);

	xer_fprint(stdout, &asn_DEF_DNDSMessage, msg);

	DNDSMessage_del(msg);
}

void show_P2pRequest_dnm()
{
	DNDSMessage_t *msg;

	msg = decode();
	DNDSMessage_printf(msg);
	DNMessage_printf(msg);
	P2pRequest_printf(msg);
}

void test_P2pRequest_dnm()
{
	/// Building a P2pRequest ///

	uint8_t macAddrSrc[ETH_ALEN] = { 0xa, 0xb, 0xc, 0xa, 0xb, 0xc };
	uint8_t macAddrDst[ETH_ALEN] = { 0xc, 0xb, 0xa, 0xc, 0xb, 0xa };

	DNDSMessage_t *msg;	// a DNDS Message

	DNDSMessage_new(&msg);
	DNDSMessage_set_channel(msg, 0);
	DNDSMessage_set_pdu(msg, pdu_PR_dnm);	// Dynamic Network Message

	DNMessage_set_seqNumber(msg, 801);
	DNMessage_set_ackNumber(msg, 0);
	DNMessage_set_operation(msg, dnop_PR_p2pRequest);

	P2pRequest_set_ipLocal(msg, "192.168.10.3");
	P2pRequest_set_macAddrSrc(msg, macAddrSrc);
	P2pRequest_set_macAddrDst(msg, macAddrDst);

	/// Encoding part

	asn_enc_rval_t ec;	// Encoder return value
	FILE *fp = fopen("dnds.ber", "wb"); // BER output
	ec = der_encode(&asn_DEF_DNDSMessage, msg, write_out, fp);
	fclose(fp);

	xer_fprint(stdout, &asn_DEF_DNDSMessage, msg);

	DNDSMessage_del(msg);
}

void show_P2pResponse_dnm()
{
	DNDSMessage_t *msg;

	msg = decode();
	DNDSMessage_printf(msg);
	DNMessage_printf(msg);
	P2pResponse_printf(msg);
}

void test_P2pResponse_dnm()
{
	/// Building a P2pRequest ///

	uint8_t macAddrDst[ETH_ALEN] = { 0xc, 0xb, 0xa, 0xc, 0xb, 0xa };

	DNDSMessage_t *msg;	// a DNDS Message

	DNDSMessage_new(&msg);
	DNDSMessage_set_channel(msg, 0);
	DNDSMessage_set_pdu(msg, pdu_PR_dnm);	// Dynamic Network Message

	DNMessage_set_seqNumber(msg, 0);
	DNMessage_set_ackNumber(msg, 801);
	DNMessage_set_operation(msg, dnop_PR_p2pResponse);

	P2pResponse_set_macAddrDst(msg, macAddrDst);
	P2pResponse_set_ipAddrDst(msg, "66.55.44.33");
	P2pResponse_set_port(msg, 9000);
	P2pResponse_set_result(msg, DNDSResult_success);

	/// Encoding part

	asn_enc_rval_t ec;	// Encoder return value
	FILE *fp = fopen("dnds.ber", "wb"); // BER output
	ec = der_encode(&asn_DEF_DNDSMessage, msg, write_out, fp);
	fclose(fp);

	xer_fprint(stdout, &asn_DEF_DNDSMessage, msg);

	DNDSMessage_del(msg);
}

void show_AuthRequest_dnm()
{
	DNDSMessage_t *msg;

	msg = decode();
	DNDSMessage_printf(msg);
	DNMessage_printf(msg);
	AuthRequest_printf(msg);
}

void test_AuthRequest_dnm()
{
	/// Building an AuthRequest ///

	DNDSMessage_t *msg;	// a DNDS Message

	DNDSMessage_new(&msg);
	DNDSMessage_set_channel(msg, 0);
	DNDSMessage_set_pdu(msg, pdu_PR_dnm);	// Dynamic Network Message

	DNMessage_set_seqNumber(msg, 100);
	DNMessage_set_ackNumber(msg, 0);
	DNMessage_set_operation(msg, dnop_PR_authRequest);

	AuthRequest_set_certName(msg, "nib@1", 5);

	/// Encoding part

	asn_enc_rval_t ec;	// Encoder return value
	FILE *fp = fopen("dnds.ber", "wb"); // BER output
	ec = der_encode(&asn_DEF_DNDSMessage, msg, write_out, fp);
	fclose(fp);

	xer_fprint(stdout, &asn_DEF_DNDSMessage, msg);

	DNDSMessage_del(msg);
}

void show_AuthResponse_dnm()
{
	DNDSMessage_t *msg;

	msg = decode();
	DNDSMessage_printf(msg);
	DNMessage_printf(msg);
	AuthResponse_printf(msg);
}

void test_AuthResponse_dnm()
{
	/// Building an AuthRequest ///

	DNDSMessage_t *msg;	// a DNDS Message

	DNDSMessage_new(&msg);
	DNDSMessage_set_channel(msg, 0);
	DNDSMessage_set_pdu(msg, pdu_PR_dnm);	// Dynamic Network Message

	DNMessage_set_seqNumber(msg, 0);
	DNMessage_set_ackNumber(msg, 100);
	DNMessage_set_operation(msg, dnop_PR_authResponse);

	AuthResponse_set_result(msg, DNDSResult_success);

	/// Encoding part

	asn_enc_rval_t ec;	// Encoder return value
	FILE *fp = fopen("dnds.ber", "wb"); // BER output
	ec = der_encode(&asn_DEF_DNDSMessage, msg, write_out, fp);
	fclose(fp);

	xer_fprint(stdout, &asn_DEF_DNDSMessage, msg);

	DNDSMessage_del(msg);
}

void show_AuthRequest()
{
	DNDSMessage_t *msg;

	msg = decode();
	DNDSMessage_printf(msg);
	DSMessage_printf(msg);
	AuthRequest_printf(msg);
}

void test_AuthRequest()
{
	/// Building an AuthRequest ///

	DNDSMessage_t *msg;	// a DNDS Message

	DNDSMessage_new(&msg);
	DNDSMessage_set_channel(msg, 0);
	DNDSMessage_set_pdu(msg, pdu_PR_dsm);	// Directory Service Message

	DSMessage_set_seqNumber(msg, 100);
	DSMessage_set_ackNumber(msg, 0);
	DSMessage_set_operation(msg, dsop_PR_authRequest);

	AuthRequest_set_certName(msg, "nib@1", 5);

	/// Encoding part

	asn_enc_rval_t ec;	// Encoder return value
	FILE *fp = fopen("dnds.ber", "wb"); // BER output
	ec = der_encode(&asn_DEF_DNDSMessage, msg, write_out, fp);
	fclose(fp);

	xer_fprint(stdout, &asn_DEF_DNDSMessage, msg);

	DNDSMessage_del(msg);
}

void show_AuthResponse()
{
	DNDSMessage_t *msg;

	msg = decode();
	DNDSMessage_printf(msg);
	DSMessage_printf(msg);
	AuthResponse_printf(msg);
}

void test_AuthResponse()
{
	/// Building an AuthResponse ///

	DNDSMessage_t *msg;	// a DNDS Message

	DNDSMessage_new(&msg);
	DNDSMessage_set_channel(msg, 0);
	DNDSMessage_set_pdu(msg, pdu_PR_dsm);	// Directory Service Message

	DSMessage_set_seqNumber(msg, 0);
	DSMessage_set_ackNumber(msg, 100);
	DSMessage_set_operation(msg, dsop_PR_authResponse);

	AuthResponse_set_result(msg, DNDSResult_success);

	/// Encoding part

	asn_enc_rval_t ec;	// Encoder return value
	FILE *fp = fopen("dnds.ber", "wb"); // BER output
	ec = der_encode(&asn_DEF_DNDSMessage, msg, write_out, fp);
	fclose(fp);

	xer_fprint(stdout, &asn_DEF_DNDSMessage, msg);

	DNDSMessage_del(msg);
}

void show_DelRequest()
{
	DNDSMessage_t *msg;

	msg = decode();
	DNDSMessage_printf(msg);
	DSMessage_printf(msg);
	DelRequest_printf(msg);

	DNDSObject_t *obj;
	DelRequest_get_object(msg, &obj);
	DNDSObject_printf(obj);
}

void test_DelRequest()
{
	/// Building a DelRequest ///

	DNDSMessage_t *msg;	// a DNDS Message
	DNDSObject_t *objAcl;	// a DNDS Object

	DNDSMessage_new(&msg);
	DNDSMessage_set_channel(msg, 0);
	DNDSMessage_set_pdu(msg, pdu_PR_dsm);	// Directory Service Message

	DSMessage_set_seqNumber(msg, 200);
	DSMessage_set_ackNumber(msg, 0);
	DSMessage_set_operation(msg, dsop_PR_delRequest);

	DelRequest_set_objectType(msg, DNDSObject_PR_acl, &objAcl);

	Acl_set_id(objAcl, 1);
	Acl_set_contextId(objAcl, 2);
	Acl_set_description(objAcl, "une description", 15);

	/// Encoding part

	asn_enc_rval_t ec;	// Encoder return value
	FILE *fp = fopen("dnds.ber", "wb"); // BER output
	ec = der_encode(&asn_DEF_DNDSMessage, msg, write_out, fp);
	fclose(fp);

	xer_fprint(stdout, &asn_DEF_DNDSMessage, msg);

	DNDSMessage_del(msg);
}

void show_DelResponse()
{
	DNDSMessage_t *msg;

	msg = decode();
	DNDSMessage_printf(msg);
	DSMessage_printf(msg);
	DelResponse_printf(msg);
}

void test_DelResponse()
{
	/// Building a DelResponse ///

	DNDSMessage_t *msg;	// a DNDS Message

	DNDSMessage_new(&msg);
	DNDSMessage_set_channel(msg, 0);
	DNDSMessage_set_pdu(msg, pdu_PR_dsm);	// Directory Service Message

	DSMessage_set_seqNumber(msg, 0);
	DSMessage_set_ackNumber(msg, 200);
	DSMessage_set_operation(msg, dsop_PR_delResponse);

	DelResponse_set_result(msg, DNDSResult_success);

	/// Encoding part

	asn_enc_rval_t ec;	// Encoder return value
	FILE *fp = fopen("dnds.ber", "wb"); // BER output
	ec = der_encode(&asn_DEF_DNDSMessage, msg, write_out, fp);
	fclose(fp);

	xer_fprint(stdout, &asn_DEF_DNDSMessage, msg);

	DNDSMessage_del(msg);
}

void show_ModifyRequest()
{
	DNDSMessage_t *msg;

	msg = decode();
	DNDSMessage_printf(msg);
	DSMessage_printf(msg);
	ModifyRequest_printf(msg);

	DNDSObject_t *obj;
	ModifyRequest_get_object(msg, &obj);
	DNDSObject_printf(obj);
}

void test_ModifyRequest()
{
	/// Building a ModifyRequest ///

	DNDSMessage_t *msg;		// a DNDS Message
	DNDSObject_t *objAclGroup;

	DNDSMessage_new(&msg);
	DNDSMessage_set_channel(msg, 0);
	DNDSMessage_set_pdu(msg, pdu_PR_dsm);

	DSMessage_set_seqNumber(msg, 300);
	DSMessage_set_ackNumber(msg, 0);
	DSMessage_set_operation(msg, dsop_PR_modifyRequest);

	ModifyRequest_set_objectType(msg, DNDSObject_PR_aclgroup, &objAclGroup);

	AclGroup_set_id(objAclGroup, 1);
	AclGroup_set_contextId(objAclGroup, 1);
	AclGroup_set_name(objAclGroup, "group-name", 10);
	AclGroup_set_description(objAclGroup, "a description", 13);

	/// Encoding part

	asn_enc_rval_t ec;	// Encoder return value
	FILE *fp = fopen("dnds.ber", "wb"); // BER output
	ec = der_encode(&asn_DEF_DNDSMessage, msg, write_out, fp);
	fclose(fp);

	xer_fprint(stdout, &asn_DEF_DNDSMessage, msg);

	DNDSMessage_del(msg);
}

void show_ModifyResponse()
{
	DNDSMessage_t *msg;

	msg = decode();
	DNDSMessage_printf(msg);
	DSMessage_printf(msg);
	ModifyResponse_printf(msg);
}

void test_ModifyResponse()
{
	/// Building a ModifyResponse ///

	DNDSMessage_t *msg;	// a DNDS Message

	DNDSMessage_new(&msg);
	DNDSMessage_set_channel(msg, 0);
	DNDSMessage_set_pdu(msg, pdu_PR_dsm);

	DSMessage_set_seqNumber(msg, 0);
	DSMessage_set_ackNumber(msg, 300);
	DSMessage_set_operation(msg, dsop_PR_modifyResponse);

	ModifyResponse_set_result(msg, DNDSResult_success);

	/// Encoding part

	asn_enc_rval_t ec;	// Encoder return value
	FILE *fp = fopen("dnds.ber", "wb"); // BER output
	ec = der_encode(&asn_DEF_DNDSMessage, msg, write_out, fp);
	fclose(fp);

	xer_fprint(stdout, &asn_DEF_DNDSMessage, msg);

	DNDSMessage_del(msg);
}

void show_NetinfoRequest()
{
	DNDSMessage_t *msg;

	msg = decode();
	DNDSMessage_printf(msg);
	DNMessage_printf(msg);
}

void test_NetinfoRequest()
{
	/// Building a NetinfoRequest ///

	DNDSMessage_t *msg;	// a DNDS Message

	DNDSMessage_new(&msg);
	DNDSMessage_set_channel(msg, 0);
	DNDSMessage_set_pdu(msg, pdu_PR_dnm);

	DNMessage_set_seqNumber(msg, 600);
	DNMessage_set_ackNumber(msg, 0);
	DNMessage_set_operation(msg, dnop_PR_netinfoRequest);

	/// Encoding part

	asn_enc_rval_t ec;	// Encoder return value
	FILE *fp = fopen("dnds.ber", "wb"); // BER output
	ec = der_encode(&asn_DEF_DNDSMessage, msg, write_out, fp);
	fclose(fp);

	xer_fprint(stdout, &asn_DEF_DNDSMessage, msg);

	DNDSMessage_del(msg);
}

void show_NetinfoResponse()
{
	DNDSMessage_t *msg;

	msg = decode();
	DNDSMessage_printf(msg);
	DNMessage_printf(msg);
	NetinfoResponse_printf(msg);
}

void test_NetinfoResponse()
{
	/// Building a NetinfoResponse ///

	DNDSMessage_t *msg;	// a DNDS Message

	DNDSMessage_new(&msg);
	DNDSMessage_set_channel(msg, 0);
	DNDSMessage_set_pdu(msg, pdu_PR_dnm);

	DNMessage_set_seqNumber(msg, 0);
	DNMessage_set_ackNumber(msg, 600);
	DNMessage_set_operation(msg, dnop_PR_netinfoResponse);

	NetinfoResponse_set_ipAddress(msg, "192.168.10.5");
	NetinfoResponse_set_netmask(msg, "255.255.255.0");
	NetinfoResponse_set_result(msg, DNDSResult_success);

	/// Encoding part

	asn_enc_rval_t ec;	// Encoder return value
	FILE *fp = fopen("dnds.ber", "wb"); // BER output
	ec = der_encode(&asn_DEF_DNDSMessage, msg, write_out, fp);
	fclose(fp);

	xer_fprint(stdout, &asn_DEF_DNDSMessage, msg);

	DNDSMessage_del(msg);
}

void show_SearchRequest()
{
	DNDSMessage_t *msg;

	msg = decode();
	DNDSMessage_printf(msg);
	DSMessage_printf(msg);
	SearchRequest_printf(msg);

	DNDSObject_t *obj;
	SearchRequest_get_object(msg, &obj);
	DNDSObject_printf(obj);
}

void test_SearchRequest()
{
	/// Building a SearchRequest()

	DNDSMessage_t *msg;	// a DNDS Message
	DNDSObject_t *objIpPool; // a DNDS Object

	DNDSMessage_new(&msg);
	DNDSMessage_set_channel(msg, 0);
	DNDSMessage_set_pdu(msg, pdu_PR_dsm);

	DSMessage_set_seqNumber(msg, 400);
	DSMessage_set_ackNumber(msg, 0);
	DSMessage_set_operation(msg, dsop_PR_searchRequest);

	SearchRequest_set_objectType(msg, DNDSObject_PR_ippool, &objIpPool);

	IpPool_set_id(objIpPool, 1);
	IpPool_set_ipLocal(objIpPool, "192.168.0.1");
	IpPool_set_ipBegin(objIpPool, "192.168.0.2");
	IpPool_set_ipEnd(objIpPool, "192.168.0.10");
	IpPool_set_netmask(objIpPool, "255.255.255.0");

	/// Encoding part

	asn_enc_rval_t ec;	// Encoder return value
	FILE *fp = fopen("dnds.ber", "wb"); // BER output
	ec = der_encode(&asn_DEF_DNDSMessage, msg, write_out, fp);
	fclose(fp);

	xer_fprint(stdout, &asn_DEF_DNDSMessage, msg);

	DNDSMessage_del(msg);
}

void show_SearchResponse()
{
	DNDSMessage_t *msg;

	msg = decode();
	DNDSMessage_printf(msg);
	DSMessage_printf(msg);
	SearchResponse_printf(msg);

	DNDSObject_t *obj;
	uint32_t count; int ret;

	SearchResponse_get_object_count(msg, &count);

	while (count-- > 0) {

		ret = SearchResponse_get_object(msg, &obj);
		if (ret == DNDS_success && obj != NULL) {
			DNDSObject_printf(obj);
		}
	}
}

void test_SearchResponse()
{
	/// Building a SearchResponse

	DNDSMessage_t *msg;	// A DNDS Message

	DNDSMessage_new(&msg);
	DNDSMessage_set_channel(msg, 0);
	DNDSMessage_set_pdu(msg, pdu_PR_dsm);

	DSMessage_set_seqNumber(msg, 0);
	DSMessage_set_ackNumber(msg, 400);
	DSMessage_set_operation(msg, dsop_PR_searchResponse);

	SearchResponse_set_result(msg, DNDSResult_success);

/// objAcl
	DNDSObject_t *objAcl;
	DNDSObject_new(&objAcl);
	DNDSObject_set_objectType(objAcl, DNDSObject_PR_acl);

	Acl_set_id(objAcl, 3);
	Acl_set_contextId(objAcl, 10);
	Acl_set_description(objAcl, "desc", 4);

	SearchResponse_add_object(msg, objAcl);

/// objAclGroup
	DNDSObject_t *objAclGroup;
	DNDSObject_new(&objAclGroup);
	DNDSObject_set_objectType(objAclGroup, DNDSObject_PR_aclgroup);

	AclGroup_set_id(objAclGroup, 5);
	AclGroup_set_contextId(objAclGroup, 10);
	AclGroup_set_name(objAclGroup, "nico", 4);
	AclGroup_set_description(objAclGroup, "desc", 4);

	SearchResponse_add_object(msg, objAclGroup);

/// objIpPool
	DNDSObject_t *objIpPool;
	DNDSObject_new(&objIpPool);
	DNDSObject_set_objectType(objIpPool, DNDSObject_PR_ippool);

	IpPool_set_id(objIpPool, 3);
	IpPool_set_ipLocal(objIpPool, "192.168.0.1");
	IpPool_set_ipBegin(objIpPool, "192.168.0.2");
	IpPool_set_ipEnd(objIpPool, "192.168.0.10");
	IpPool_set_netmask(objIpPool, "255.255.255.255");

	SearchResponse_add_object(msg, objIpPool);

/// objContext
	DNDSObject_t *objContext;
	DNDSObject_new(&objContext);
	DNDSObject_set_objectType(objContext, DNDSObject_PR_context);

	Context_set_id(objContext, 40);
	Context_set_ippoolId(objContext, 20);
	Context_set_dnsZone(objContext, "dnsZone", 7);
	Context_set_dnsSerial(objContext, 666);
	Context_set_vhost(objContext, "vhost", 5);
	Context_set_certificate(objContext, "certificate", 11);
	Context_set_certificateKey(objContext, "key", 3);
	Context_set_description(objContext, "desc", 4);

	SearchResponse_add_object(msg, objContext);

/// objHost
	DNDSObject_t *objHost;
	DNDSObject_new(&objHost);
	DNDSObject_set_objectType(objHost, DNDSObject_PR_host);

	uint8_t macAddress[ETH_ALEN] = { 0xa, 0xb, 0xc, 0xa, 0xb, 0xc };

	Host_set_id(objHost, 33);
	Host_set_contextId(objHost, 10);
	Host_set_peerId(objHost, 11);
	Host_set_name(objHost, "hostname", 8);
	Host_set_macAddress(objHost, macAddress);
	Host_set_ipAddress(objHost, "66.43.24.12");
	Host_set_status(objHost, 1);

	SearchResponse_add_object(msg, objHost);

/// objNode
	DNDSObject_t *objNode;
	DNDSObject_new(&objNode);
	DNDSObject_set_objectType(objNode, DNDSObject_PR_node);

	Node_set_id(objNode, 3);
	Node_set_name(objNode, "node-name", 9);
	Node_set_ipAddress(objNode, "192.168.10.2");
	Node_set_certificate(objNode, "certificate", 11);
	Node_set_certificateKey(objNode, "key", 3);
	Node_set_status(objNode, 0);

	SearchResponse_add_object(msg, objNode);

/// Peer
	DNDSObject_t *objPeer;
	DNDSObject_new(&objPeer);
	DNDSObject_set_objectType(objPeer, DNDSObject_PR_peer);

	Peer_set_id(objPeer, 4);
	Peer_set_contextId(objPeer, 10);
	Peer_set_ipAddress(objPeer, "10.0.3.1");
	Peer_set_certificate(objPeer, "certificate", 11);
	Peer_set_certificateKey(objPeer, "key", 3);
	Peer_set_status(objPeer, 2);

	SearchResponse_add_object(msg, objPeer);

/// User1
	DNDSObject_t *objUser1;	// A User Object
	DNDSObject_new(&objUser1);
	DNDSObject_set_objectType(objUser1, DNDSObject_PR_user);

	User_set_id(objUser1, 1);
	User_set_contextId(objUser1, 1);
	User_set_name(objUser1, "1icboul", 7);
	User_set_password(objUser1, "1wd1wd", 6);
	User_set_firstname(objUser1, "1icolas", 7);
	User_set_lastname(objUser1, "1ouliane", 8);
	User_set_email(objUser1, "1icboul@gmail.com", 15);
	User_set_role(objUser1, 0);
	User_set_status(objUser1, 0);

	SearchResponse_add_object(msg, objUser1);

/// User2
	DNDSObject_t *objUser2;	// A User Object
	DNDSObject_new(&objUser2);
	DNDSObject_set_objectType(objUser2, DNDSObject_PR_user);

	User_set_id(objUser2, 2);
	User_set_contextId(objUser2, 2);
	User_set_name(objUser2, "2icboul", 6);
	User_set_password(objUser2, "2wd2wd", 6);
	User_set_firstname(objUser2, "2icolas", 7);
	User_set_lastname(objUser2, "2ouliane", 8);
	User_set_email(objUser2, "2icboul@gmail.com", 15);
	User_set_role(objUser2, 0);
	User_set_status(objUser2, 0);

	SearchResponse_add_object(msg, objUser2);

	/// Encoding part

	asn_enc_rval_t ec;	// Encoder return value
	FILE *fp = fopen("dnds.ber", "wb"); // BER output
	ec = der_encode(&asn_DEF_DNDSMessage, msg, write_out, fp);
	fclose(fp);

	xer_fprint(stdout, &asn_DEF_DNDSMessage, msg);

	DNDSMessage_del(msg);
}

void test_TerminateRequest()
{
	/// Building a TerminateRequest ///

	DNDSMessage_t *msg;	// a DNDS Message

	DNDSMessage_new(&msg);
	DNDSMessage_set_channel(msg, 0);
	DNDSMessage_set_pdu(msg, pdu_PR_dsm);

	DSMessage_set_seqNumber(msg, 0);
	DSMessage_set_ackNumber(msg, 400);
	DSMessage_set_operation(msg, dsop_PR_terminateRequest);

	/// Encoding part

	asn_enc_rval_t ec;	// Encoder return value
	FILE *fp = fopen("dnds.ber", "wb"); // BER output
	ec = der_encode(&asn_DEF_DNDSMessage, msg, write_out, fp);
	fclose(fp);

	xer_fprint(stdout, &asn_DEF_DNDSMessage, msg);

	DNDSMessage_del(msg);
}

int main()
{
	test_DNDS_ethernet();
	show_DNDS_ethernet();

/*	test_AddRequest();
	show_AddRequest();

	test_AddResponse();
	show_AddResponse();

	test_P2pRequest_dnm();
	show_P2pRequest_dnm();

	test_P2pResponse_dnm();
	show_P2pResponse_dnm();

	test_AuthRequest_dnm();
	show_AuthRequest_dnm();

	test_AuthResponse_dnm();
	show_AuthResponse_dnm();

	test_AuthRequest();
	show_AuthRequest();

	test_AuthResponse();
	show_AuthResponse();

	test_DelRequest();
	show_DelRequest();

	test_DelResponse();
	show_DelResponse();

	test_ModifyRequest();
	show_ModifyRequest();

	test_ModifyResponse();
	show_ModifyResponse();

	test_NetinfoRequest();
	show_NetinfoRequest();

	test_NetinfoResponse();
	show_NetinfoResponse();

	test_SearchRequest();
	show_SearchRequest();

	test_SearchResponse();
	show_SearchResponse();
*/
//	test_TerminateRequest();
}
