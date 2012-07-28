
ASN_MODULE_SOURCES=	\
	DNDSMessage.c	\
	DNDSResult.c	\
	DNMessage.c	\
	DSMessage.c	\
	DNDSObject.c	\
	ObjectName.c	\
	AuthRequest.c	\
	AuthResponse.c	\
	NetinfoRequest.c	\
	NetinfoResponse.c	\
	ProvRequest.c	\
	ProvResponse.c	\
	P2pSide.c	\
	P2pRequest.c	\
	P2pResponse.c	\
	AddRequest.c	\
	AddResponse.c	\
	DelRequest.c	\
	DelResponse.c	\
	ModifyRequest.c	\
	ModifyResponse.c	\
	ConnectState.c	\
	NodeConnectInfo.c	\
	SearchType.c	\
	SearchRequest.c	\
	SearchResponse.c	\
	TerminateRequest.c	\
	Topology.c	\
	Client.c	\
	Context.c	\
	Node.c

ASN_MODULE_HEADERS=	\
	DNDSMessage.h	\
	DNDSResult.h	\
	DNMessage.h	\
	DSMessage.h	\
	DNDSObject.h	\
	ObjectName.h	\
	AuthRequest.h	\
	AuthResponse.h	\
	NetinfoRequest.h	\
	NetinfoResponse.h	\
	ProvRequest.h	\
	ProvResponse.h	\
	P2pSide.h	\
	P2pRequest.h	\
	P2pResponse.h	\
	AddRequest.h	\
	AddResponse.h	\
	DelRequest.h	\
	DelResponse.h	\
	ModifyRequest.h	\
	ModifyResponse.h	\
	ConnectState.h	\
	NodeConnectInfo.h	\
	SearchType.h	\
	SearchRequest.h	\
	SearchResponse.h	\
	TerminateRequest.h	\
	Topology.h	\
	Client.h	\
	Context.h	\
	Node.h

ASN_MODULE_HEADERS+=BOOLEAN.h
ASN_MODULE_SOURCES+=BOOLEAN.c
ASN_MODULE_HEADERS+=INTEGER.h
ASN_MODULE_HEADERS+=NativeEnumerated.h
ASN_MODULE_HEADERS+=IA5String.h
ASN_MODULE_SOURCES+=IA5String.c
ASN_MODULE_SOURCES+=INTEGER.c
ASN_MODULE_HEADERS+=NULL.h
ASN_MODULE_SOURCES+=NULL.c
ASN_MODULE_SOURCES+=NativeEnumerated.c
ASN_MODULE_HEADERS+=NativeInteger.h
ASN_MODULE_SOURCES+=NativeInteger.c
ASN_MODULE_HEADERS+=PrintableString.h
ASN_MODULE_SOURCES+=PrintableString.c
ASN_MODULE_HEADERS+=asn_SEQUENCE_OF.h
ASN_MODULE_SOURCES+=asn_SEQUENCE_OF.c
ASN_MODULE_HEADERS+=asn_SET_OF.h
ASN_MODULE_SOURCES+=asn_SET_OF.c
ASN_MODULE_HEADERS+=constr_CHOICE.h
ASN_MODULE_SOURCES+=constr_CHOICE.c
ASN_MODULE_HEADERS+=constr_SEQUENCE.h
ASN_MODULE_SOURCES+=constr_SEQUENCE.c
ASN_MODULE_HEADERS+=constr_SEQUENCE_OF.h
ASN_MODULE_SOURCES+=constr_SEQUENCE_OF.c
ASN_MODULE_HEADERS+=constr_SET_OF.h
ASN_MODULE_SOURCES+=constr_SET_OF.c
ASN_MODULE_HEADERS+=asn_application.h
ASN_MODULE_HEADERS+=asn_system.h
ASN_MODULE_HEADERS+=asn_codecs.h
ASN_MODULE_HEADERS+=asn_internal.h
ASN_MODULE_HEADERS+=OCTET_STRING.h
ASN_MODULE_SOURCES+=OCTET_STRING.c
ASN_MODULE_HEADERS+=BIT_STRING.h
ASN_MODULE_SOURCES+=BIT_STRING.c
ASN_MODULE_SOURCES+=asn_codecs_prim.c
ASN_MODULE_HEADERS+=asn_codecs_prim.h
ASN_MODULE_HEADERS+=ber_tlv_length.h
ASN_MODULE_SOURCES+=ber_tlv_length.c
ASN_MODULE_HEADERS+=ber_tlv_tag.h
ASN_MODULE_SOURCES+=ber_tlv_tag.c
ASN_MODULE_HEADERS+=ber_decoder.h
ASN_MODULE_SOURCES+=ber_decoder.c
ASN_MODULE_HEADERS+=der_encoder.h
ASN_MODULE_SOURCES+=der_encoder.c
ASN_MODULE_HEADERS+=constr_TYPE.h
ASN_MODULE_SOURCES+=constr_TYPE.c
ASN_MODULE_HEADERS+=constraints.h
ASN_MODULE_SOURCES+=constraints.c
ASN_MODULE_HEADERS+=xer_support.h
ASN_MODULE_SOURCES+=xer_support.c
ASN_MODULE_HEADERS+=xer_decoder.h
ASN_MODULE_SOURCES+=xer_decoder.c
ASN_MODULE_HEADERS+=xer_encoder.h
ASN_MODULE_SOURCES+=xer_encoder.c
ASN_MODULE_HEADERS+=per_support.h
ASN_MODULE_SOURCES+=per_support.c
ASN_MODULE_HEADERS+=per_decoder.h
ASN_MODULE_SOURCES+=per_decoder.c
ASN_MODULE_HEADERS+=per_encoder.h
ASN_MODULE_SOURCES+=per_encoder.c
ASN_MODULE_HEADERS+=per_opentype.h
ASN_MODULE_SOURCES+=per_opentype.c

# do not install libasn1 -> convenience library
noinst_LTLIBRARIES = libasn1.la
libasn1_la_SOURCES=$(ASN_MODULE_SOURCES)
libasn1_include_HEADERS=$(ASN_MODULE_HEADERS)

# libasn1 include should be in ../include/dnds/asn1
libasn1_includedir=$(includedir)/dnds/asn1
ASN_MODULEdir=$(includedir)/dnds/asn1
