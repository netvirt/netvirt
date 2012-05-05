#!/usr/bin/env python

# Dynamic-Network-Directory-Service-Protocol-V1
# Copyright (C) Nicolas Bouliane - 2012

from pyasn1.type import univ, namedtype, namedval, tag, constraint
from pyasn1.type import char
from pyasn1.codec.ber import encoder, decoder

class SearchType(univ.Enumerated):
    namedValues = namedval.NamedValues(
        ('all', 1),
        ('sequence', 2),
        ('object', 3)
    )

class ObjectName(univ.Enumerated):
    namedValues = namedval.NamedValues(
        ('acl', 1),
        ('aclgroup', 2),
        ('ippool', 3),
        ('context', 4),
        ('host', 5),
        ('node', 6),
        ('peer', 7),
        ('permission', 8),
        ('user', 9)
    )

class SearchRequest(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('searchtype', SearchType().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 0))),
        namedtype.NamedType('objectname', ObjectName().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 1)))
        )

class DNDSResult(univ.Enumerated):
    namedValues = namedval.NamedValues(
        ('success', 1),
        ('operationError', 2),
        ('protocolError', 3),
        ('noSuchObject', 4),
        ('busy', 5),
        ('secureStepUp', 6),
        ('insufficientAccessRights', 7)
    )

class Topology(univ.Enumerated):
    namedValues = namedval.NamedValues(
        ('mesh', 1),
        ('hubspoke', 2),
        ('gateway', 3)
        )

class DSop(univ.Choice):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('searchRequest', SearchRequest().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 9)))
        )

class DSMessage(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('seqNumber', univ.Integer().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 0))),
        namedtype.NamedType('ackNumber', univ.Integer().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 1))),
	namedtype.NamedType('dsop', DSop().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 2)))
        )

class Pdu(univ.Choice):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('dnm', univ.Integer().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 0))),
        namedtype.NamedType('dsm', DSMessage().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 1))),
        namedtype.NamedType('ethernet', univ.Integer().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 2)))
        )

class DNDSMessage(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('version', univ.Integer().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 0))),
        namedtype.NamedType('channel', univ.Integer().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 1))),
        namedtype.NamedType('pdu', Pdu().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 2)))
        )
"""
req = SearchRequest()
req.setComponentByName('searchtype', 'all')
req.setComponentByName('objectname', 'context')

dsop = DSop()
dsop.setComponentByName('searchRequest', req)

dsm = DSMessage()
dsm.setComponentByName('seqNumber', '1')
dsm.setComponentByName('ackNumber', '1')
dsm.setComponentByName('dsop', dsop)

pdu = Pdu()
pdu.setComponentByName('dsm', dsm)

msg = DNDSMessage()
msg.setComponentByName('version', '1')
msg.setComponentByName('channel', '0')
msg.setComponentByName('pdu', pdu)
"""

f = open('dnds.ber', 'rb')
substrate = f.read()
f.close()
my_msg, substrate = decoder.decode(substrate, asn1Spec=DNDSMessage())

