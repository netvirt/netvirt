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

class Topology(univ.Enumerated):
    namedValues = namedval.NamedValues(
        ('mesh', 1),
        ('hubspoke', 2),
        ('gateway', 3)
    )

class Context(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.OptionalNamedType('id', univ.Integer().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 0))),
        namedtype.NamedType('clientId', univ.Integer().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 1))),
        namedtype.NamedType('topology', Topology().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 2))),
        namedtype.OptionalNamedType('description', char.PrintableString().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 3))),
        namedtype.NamedType('network', univ.OctetString().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 4))),
        namedtype.NamedType('netmask', univ.OctetString().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 5))),
        namedtype.OptionalNamedType('serverCert',char.PrintableString().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 6))),
        namedtype.OptionalNamedType('serverPrivkey', char.PrintableString().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 7))),
        namedtype.OptionalNamedType('trustedCert', char.PrintableString().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 8))),
    )

class Peer(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('contextId', univ.Integer().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 0))),
        namedtype.OptionalNamedType('description', char.PrintableString().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 1))),
        namedtype.OptionalNamedType('uuid', char.PrintableString().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 2))),
        namedtype.OptionalNamedType('certificate', char.PrintableString().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 3))),
        namedtype.OptionalNamedType('certificateKey', univ.BitString().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 4))),
        namedtype.OptionalNamedType('status', univ.Integer().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 5))),
    )

class Client(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('id', univ.Integer().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 0))),
        namedtype.NamedType('username', char.PrintableString().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 1))),
        namedtype.NamedType('password', char.PrintableString().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 2))),
        namedtype.NamedType('firstname', char.PrintableString().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 3))),
        namedtype.NamedType('lastname', char.PrintableString().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 4))),
        namedtype.NamedType('email', char.IA5String().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 5))),
        namedtype.NamedType('company', char.PrintableString().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 6))),
        namedtype.NamedType('phone', char.PrintableString().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 7))),
        namedtype.NamedType('country', char.PrintableString().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 8))),
        namedtype.NamedType('stateProvince', char.PrintableString().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 9))),
        namedtype.NamedType('city', char.PrintableString().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 10))),
        namedtype.NamedType('postalCode', char.PrintableString().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 11))),
        namedtype.NamedType('status', univ.Integer().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 12))),
    )

class WebCredential(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('clientId', univ.Integer().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 0))),
        namedtype.OptionalNamedType('username', char.PrintableString().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 1))),
        namedtype.OptionalNamedType('password', char.PrintableString().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 2))),
    )

class DNDSObject(univ.Choice):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('context', Context().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 3))),
        namedtype.NamedType('peer', Peer().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 6))),
        namedtype.NamedType('client', Client().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 8))),
        namedtype.NamedType('webcredential', WebCredential().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 9)))
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
        ('client', 9)
    )

class SearchRequest(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('searchtype', SearchType().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 0))),
        namedtype.OptionalNamedType('objectname', ObjectName().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 1))),
        namedtype.NamedType('object', DNDSObject().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 2)))
        )

class objects(univ.SequenceOf):
    componentType = DNDSObject()

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

class SearchResponse(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('searchtype', SearchType().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 0))),
        namedtype.NamedType('result', DNDSResult().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 1))),
        namedtype.NamedType('objects', objects().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 2)))
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
        namedtype.NamedType('addRequest', DNDSObject().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 3))),
        namedtype.NamedType('searchRequest', SearchRequest().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 9))),
        namedtype.NamedType('searchResponse', SearchResponse().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 10)))
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

f = open('dnds.ber', 'rb')
substrate = f.read()
f.close()
my_msg, substrate = decoder.decode(substrate, asn1Spec=DNDSMessage())

print(my_msg.prettyPrint())


"""
msg = DNDSMessage()
msg.setComponentByName('version', '1')
msg.setComponentByName('channel', '0')

pdu = msg.setComponentByName('pdu').getComponentByName('pdu')
dsm = pdu.setComponentByName('dsm').getComponentByName('dsm')

dsm.setComponentByName('seqNumber', '1')
dsm.setComponentByName('ackNumber', '1')

dsop = dsm.setComponentByName('dsop').getComponentByName('dsop')

obj = dsop.setComponentByName('addRequest').getComponentByName('addRequest')
client = obj.setComponentByName('client').getComponentByName('client')

client.setComponentByName('id', '0')
client.setComponentByName('username', 'test-username')
client.setComponentByName('password', 'test-password')
client.setComponentByName('firstname', 'test-firstname')
client.setComponentByName('lastname', 'test-lastname')
client.setComponentByName('email', 'test-email')
client.setComponentByName('company', 'test-company')
client.setComponentByName('phone', 'test-phone')
client.setComponentByName('country', 'test-country')
client.setComponentByName('stateProvince', 'test-stateProvince')
client.setComponentByName('city', 'test-city')
client.setComponentByName('postalCode', 'test-postalCode')
client.setComponentByName('status', '0')

print(msg.prettyPrint())

f = open('dnds.ber', 'wb')
f.write(encoder.encode(msg))
f.close()

f = open('dnds.ber', 'rb')
substrate = f.read()
f.close()
my_msg, substrate = decoder.decode(substrate, asn1Spec=DNDSMessage())

print(my_msg.prettyPrint())

"""
