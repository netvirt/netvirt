#!/usr/bin/env python

# Copyright (C) Nicolas Bouliane - 2012
# DSC> Directory service Client

import socket
import ssl
import pprint
import time
from dnds import *

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
ssl_sock = ssl.wrap_socket(sock,
                           server_side=False,
                           ca_certs="/etc/dnds/cert-demo/dsd_cert.pem",
                           certfile="/etc/dnds/cert-demo/dnd_cert.pem",
                           keyfile="/etc/dnds/cert-demo/dnd_privkey.pem",
                           ssl_version=ssl.PROTOCOL_TLSv1)

ssl_sock.connect(('127.0.0.1', 9091))

print repr(ssl_sock.getpeername())
print ssl_sock.cipher()
print pprint.pformat(ssl_sock.getpeercert())

msg = DNDSMessage()
msg.setComponentByName('version', '1')
msg.setComponentByName('channel', '0')
pdu = msg.setComponentByName('pdu').getComponentByName('pdu')
dsm = pdu.setComponentByName('dsm').getComponentByName('dsm')

dsm.setComponentByName('seqNumber', '1')
dsm.setComponentByName('ackNumber', '1')
dsop = dsm.setComponentByName('dsop').getComponentByName('dsop')

req = dsop.setComponentByName('searchRequest').getComponentByName('searchRequest')
req.setComponentByName('searchtype', 'all')
req.setComponentByName('objectname', 'context')

ssl_sock.write(encoder.encode(msg))

time.sleep(3)

data = ssl_sock.read()

f = open('data.bin', 'wb')
f.write(data)
f.close()

ssl_sock.close()
