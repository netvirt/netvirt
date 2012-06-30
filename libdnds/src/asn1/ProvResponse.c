/*
 * Generated by asn1c-0.9.23 (http://lionet.info/asn1c)
 * From ASN.1 module "DNDS"
 * 	found in "dnds.asn1"
 */

#include "ProvResponse.h"

static asn_TYPE_member_t asn_MBR_ProvResponse_1[] = {
	{ ATF_POINTER, 3, offsetof(struct ProvResponse, certificate),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_PrintableString,
		0,	/* Defer constraints checking to the member type */
		0,	/* PER is not compiled, use -gen-PER */
		0,
		"certificate"
		},
	{ ATF_POINTER, 2, offsetof(struct ProvResponse, certificateKey),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_PrintableString,
		0,	/* Defer constraints checking to the member type */
		0,	/* PER is not compiled, use -gen-PER */
		0,
		"certificateKey"
		},
	{ ATF_POINTER, 1, offsetof(struct ProvResponse, trustedCert),
		(ASN_TAG_CLASS_CONTEXT | (2 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_PrintableString,
		0,	/* Defer constraints checking to the member type */
		0,	/* PER is not compiled, use -gen-PER */
		0,
		"trustedCert"
		},
};
static ber_tlv_tag_t asn_DEF_ProvResponse_tags_1[] = {
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static asn_TYPE_tag2member_t asn_MAP_ProvResponse_tag2el_1[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* certificate at 120 */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 }, /* certificateKey at 121 */
    { (ASN_TAG_CLASS_CONTEXT | (2 << 2)), 2, 0, 0 } /* trustedCert at 122 */
};
static asn_SEQUENCE_specifics_t asn_SPC_ProvResponse_specs_1 = {
	sizeof(struct ProvResponse),
	offsetof(struct ProvResponse, _asn_ctx),
	asn_MAP_ProvResponse_tag2el_1,
	3,	/* Count of tags in the map */
	0, 0, 0,	/* Optional elements (not needed) */
	2,	/* Start extensions */
	4	/* Stop extensions */
};
asn_TYPE_descriptor_t asn_DEF_ProvResponse = {
	"ProvResponse",
	"ProvResponse",
	SEQUENCE_free,
	SEQUENCE_print,
	SEQUENCE_constraint,
	SEQUENCE_decode_ber,
	SEQUENCE_encode_der,
	SEQUENCE_decode_xer,
	SEQUENCE_encode_xer,
	0, 0,	/* No PER support, use "-gen-PER" to enable */
	0,	/* Use generic outmost tag fetcher */
	asn_DEF_ProvResponse_tags_1,
	sizeof(asn_DEF_ProvResponse_tags_1)
		/sizeof(asn_DEF_ProvResponse_tags_1[0]), /* 1 */
	asn_DEF_ProvResponse_tags_1,	/* Same as above */
	sizeof(asn_DEF_ProvResponse_tags_1)
		/sizeof(asn_DEF_ProvResponse_tags_1[0]), /* 1 */
	0,	/* No PER visible constraints */
	asn_MBR_ProvResponse_1,
	3,	/* Elements count */
	&asn_SPC_ProvResponse_specs_1	/* Additional specs */
};

