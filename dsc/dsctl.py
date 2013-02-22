#!/usr/bin/env python

# Copyright (C) Nicolas J. Bouliane - 2012
# dsctl - Directory Service Control

import signal
import socket
import ssl
import pprint
import sys

from dnds import *

class Connection:
    sock = None
    ssl_sock = None
    connected = False
    loggedin = False
    ClientId = 0

def signal_handler(signal, frame):
    pass

def dsctl_help():
    print ''
    print 'Usage:'
    print '  status'
    print '  connect <ipaddr>'
    print '  login <email,password>'
    print '  add-client <firstname,lastname,email,password,company,phone,country,stateProvince,city,postalCode>'
    print '  add-context <unique description>'
    print '  add-node <context id, unique description>'
    print '  show-context'
    print '  show-node <context id>'
    print '  logout'
    print '  disconnect'
    print '  exit'
    pass

def login(conn, arg):

    loginInfo = arg.split(',')
    if len(loginInfo) != 2:
        dsctl_help()
        return

    if conn.connected == False:
        print 'you must connect first...'
        return

    if conn.loggedin == True:
        print 'you are already logged in...'
        return

    msg = DNDSMessage()
    msg.setComponentByName('version', '1')
    msg.setComponentByName('channel', '0')
    pdu = msg.setComponentByName('pdu').getComponentByName('pdu')
    dsm = pdu.setComponentByName('dsm').getComponentByName('dsm')

    dsm.setComponentByName('seqNumber', '1')
    dsm.setComponentByName('ackNumber', '1')
    dsop = dsm.setComponentByName('dsop').getComponentByName('dsop')

    req = dsop.setComponentByName('searchRequest').getComponentByName('searchRequest')
    req.setComponentByName('searchtype', 'object')

    obj = req.setComponentByName('object').getComponentByName('object')
    client = obj.setComponentByName('client').getComponentByName('client')

    client.setComponentByName('email', loginInfo[0])
    client.setComponentByName('password', loginInfo[1])

#    print(msg.prettyPrint())
    conn.ssl_sock.write(encoder.encode(msg))

    data = conn.ssl_sock.read()

    substrate = data
    a_msg, substrate = decoder.decode(substrate, asn1Spec=DNDSMessage())
#    print(a_msg.prettyPrint())

    recv_pdu = a_msg.getComponentByName('pdu')
    recv_dsm = recv_pdu.getComponentByName('dsm')
    recv_dsop = recv_dsm.getComponentByName('dsop')
    recv_req = recv_dsop.getComponentByName('searchResponse')
    recv_objs = recv_req.getComponentByName('objects')

    for idx in range(len(recv_objs)):
        recv_obj =  recv_objs.getComponentByPosition(idx)
        recv_client = recv_obj.getComponentByName('client')
        recv_clientId = recv_client.getComponentByName('id')
 #       print "the client id is " + str(recv_clientId)

    conn.ClientId = str(recv_clientId)

    if conn.ClientId == '0':
        print 'failed to log in...'
        return

    conn.loggedin = True
    print 'ClientId: ' + conn.ClientId
    print 'you are now logged in!'

def showNode(conn, arg):

    contextId = arg

    if conn.connected == False:
        print 'you must connect first...'
        return

    if conn.loggedin == False:
        print 'you are not logged in...'
        return

    msg = DNDSMessage()
    msg.setComponentByName('version', '1')
    msg.setComponentByName('channel', '0')
    pdu = msg.setComponentByName('pdu').getComponentByName('pdu')
    dsm = pdu.setComponentByName('dsm').getComponentByName('dsm')

    dsm.setComponentByName('seqNumber', '1')
    dsm.setComponentByName('ackNumber', '1')
    dsop = dsm.setComponentByName('dsop').getComponentByName('dsop')

    req = dsop.setComponentByName('searchRequest').getComponentByName('searchRequest')
    req.setComponentByName('searchtype', 'object')

    obj = req.setComponentByName('object').getComponentByName('object')
    node = obj.setComponentByName('node').getComponentByName('node')

    node.setComponentByName('contextId', str(contextId))

    conn.ssl_sock.write(encoder.encode(msg))
    data = conn.ssl_sock.read()

    substrate = data
    a_msg, substrate = decoder.decode(substrate, asn1Spec=DNDSMessage())

    recv_pdu = a_msg.getComponentByName('pdu')
    recv_dsm = recv_pdu.getComponentByName('dsm')
    recv_dsop = recv_dsm.getComponentByName('dsop')
    recv_req = recv_dsop.getComponentByName('searchResponse')
    recv_objs = recv_req.getComponentByName('objects')

    for idx in range(len(recv_objs)):
        recv_obj =  recv_objs.getComponentByPosition(idx)
        recv_node = recv_obj.getComponentByName('node')
        recv_uuid = recv_node.getComponentByName('uuid')
        recv_provcode = recv_node.getComponentByName('provCode')
        recv_desc = recv_node.getComponentByName('description')
        recv_ipaddress = recv_node.getComponentByName('ipaddress')
        print "node uuid: " + str(recv_uuid) + ' provCode: ' + str(recv_provcode) + ' <' + recv_desc + '> ' + socket.inet_ntoa(recv_ipaddress.asOctets())

def showContext(conn):

    if conn.connected == False:
        print 'you must connect first...'
        return

    if conn.loggedin == False:
        print 'you are not logged in...'
        return

    msg = DNDSMessage()
    msg.setComponentByName('version', '1')
    msg.setComponentByName('channel', '0')
    pdu = msg.setComponentByName('pdu').getComponentByName('pdu')
    dsm = pdu.setComponentByName('dsm').getComponentByName('dsm')

    dsm.setComponentByName('seqNumber', '1')
    dsm.setComponentByName('ackNumber', '1')
    dsop = dsm.setComponentByName('dsop').getComponentByName('dsop')

    req = dsop.setComponentByName('searchRequest').getComponentByName('searchRequest')
    req.setComponentByName('searchtype', 'object')

    obj = req.setComponentByName('object').getComponentByName('object')
    context = obj.setComponentByName('context').getComponentByName('context')

    context.setComponentByName('clientId', str(conn.ClientId))
    context.setComponentByName('topology', 'mesh')
    context.setComponentByName('description', 'home network1')
    context.setComponentByName('network', '0')
    context.setComponentByName('netmask', '0')

    conn.ssl_sock.write(encoder.encode(msg))
    loop = True
    data = ""
    while loop is True:
        data += conn.ssl_sock.read()
        substrate = data
        try:
            a_msg, substrate = decoder.decode(substrate, asn1Spec=DNDSMessage())
            loop = False
        except:
            pass

    recv_pdu = a_msg.getComponentByName('pdu')
    recv_dsm = recv_pdu.getComponentByName('dsm')
    recv_dsop = recv_dsm.getComponentByName('dsop')
    recv_req = recv_dsop.getComponentByName('searchResponse')
    recv_objs = recv_req.getComponentByName('objects')

    for idx in range(len(recv_objs)):
        recv_obj =  recv_objs.getComponentByPosition(idx)
        recv_context = recv_obj.getComponentByName('context')
        recv_id = recv_context.getComponentByName('id')
        recv_desc = recv_context.getComponentByName('description')
        print "context id: " + str(recv_id) + ' <' + recv_desc + '>'

def addNode(conn, arg):

    nodeInfo = arg.split(',')
    if len(nodeInfo) != 2:
        dsctl_help()
        return

    if conn.connected == False:
        print 'you must connect first...'
        return

    if conn.loggedin == False:
        print 'you are not logged in...'
        return

    msg = DNDSMessage()
    msg.setComponentByName('version', '1')
    msg.setComponentByName('channel', '0')

    pdu = msg.setComponentByName('pdu').getComponentByName('pdu')
    dsm = pdu.setComponentByName('dsm').getComponentByName('dsm')

    dsm.setComponentByName('seqNumber', '1')
    dsm.setComponentByName('ackNumber', '1')

    dsop = dsm.setComponentByName('dsop').getComponentByName('dsop')

    obj = dsop.setComponentByName('addRequest').getComponentByName('addRequest')
    node = obj.setComponentByName('node').getComponentByName('node')

    node.setComponentByName('contextId', str(nodeInfo[0]))
    node.setComponentByName('description', str(nodeInfo[1]))

    conn.ssl_sock.write(encoder.encode(msg))

def addContext(conn, arg):

    ContextDescription = arg
    if conn.connected == False:
        print 'you must connect first...'
        return

    if conn.loggedin == False:
        print 'you are not logged in...'
        return

    msg = DNDSMessage()
    msg.setComponentByName('version', '1')
    msg.setComponentByName('channel', '0')

    pdu = msg.setComponentByName('pdu').getComponentByName('pdu')
    dsm = pdu.setComponentByName('dsm').getComponentByName('dsm')

    dsm.setComponentByName('seqNumber', '1')
    dsm.setComponentByName('ackNumber', '1')

    dsop = dsm.setComponentByName('dsop').getComponentByName('dsop')

    obj = dsop.setComponentByName('addRequest').getComponentByName('addRequest')
    context = obj.setComponentByName('context').getComponentByName('context')

    context.setComponentByName('clientId', str(conn.ClientId))
    context.setComponentByName('topology', 'mesh')
    context.setComponentByName('description', ContextDescription)
    context.setComponentByName('network', '0x2c800000')
    context.setComponentByName('netmask', '0xffffff00')

    conn.ssl_sock.write(encoder.encode(msg))

def addClient(conn, arg):

    ClientInfo = arg.split(',')
    if len(ClientInfo) != 10:
        dsctl_help()
        return

    if conn.connected == False:
        print 'you must connect first...'
        return

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

    client.setComponentByName('firstname', ClientInfo[0])
    client.setComponentByName('lastname', ClientInfo[1])
    client.setComponentByName('email', ClientInfo[2])
    client.setComponentByName('password', ClientInfo[3])
    client.setComponentByName('company', ClientInfo[4])
    client.setComponentByName('phone', ClientInfo[5])
    client.setComponentByName('country', ClientInfo[6])
    client.setComponentByName('stateProvince', ClientInfo[7])
    client.setComponentByName('city', ClientInfo[8])
    client.setComponentByName('postalCode', ClientInfo[9])
    client.setComponentByName('status', '0')

    print(msg.prettyPrint())
    print conn.ssl_sock.write(encoder.encode(msg))

def status(conn):
    if conn.connected == True:
        print 'Conntected to: ' + repr(conn.ssl_sock.getpeername())
        print conn.ssl_sock.cipher()
    else:
        print 'Not connected...'

def connect(conn, ipaddr):

    if conn.connected == True:
        print 'you are already connected!'
        return

    conn.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    conn.ssl_sock = ssl.wrap_socket(conn.sock,
                           server_side=False,
                           ca_certs="/etc/dnds/cert-demo/dsd_cert.pem",
                           certfile="/etc/dnds/cert-demo/dsc_cert.pem",
                           keyfile="/etc/dnds/cert-demo/dsc_privkey.pem",
                           ssl_version=ssl.PROTOCOL_TLSv1)

    conn.ssl_sock.connect((ipaddr, 9091))
    conn.connected = True
    print 'now connected!'

def disconnect(conn):

    if conn.connected == False:
        print 'you are already disconnected!'
        return

    conn.ssl_sock.shutdown(socket.SHUT_RDWR)
    conn.ssl_sock.close()
    conn.connected = False
    print 'now disconnected!'

def main():
    signal.signal(signal.SIGINT, signal_handler)
    loop()

def loop():

    conn = Connection()

    while True:
        line_input = raw_input('dsctl> ')
        command, sep, arg = line_input.partition(' ')

        if command == 'show-context':
            showContext(conn)

        if command == 'show-node':
            showNode(conn, arg)

        if command == 'add-context':
            addContext(conn, arg)

        if command == 'add-client':
            addClient(conn, arg)

        if command == 'add-node':
            addNode(conn, arg)

        if command == 'login':
            login(conn, arg)

        if command == 'connect':
            connect(conn, arg)

        if command == 'disconnect':
            disconnect(conn)

        if command == 'status':
            status(conn)

        if command == 'help':
            dsctl_help()

        if command == 'exit':
            sys.exit(0)

if __name__ == '__main__':
    main()
