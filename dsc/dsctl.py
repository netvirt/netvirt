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

def signal_handler(signal, frame):
    pass

def dsctl_help():
    print ''
    print 'Usage:'
    print '  connect <ipaddr>'
    print '  disconnect'
    print '  status'
    print '  exit'
    print ''
    pass

def status(conn):
    if conn.connected == True:
        print 'Conntected to: ' + repr(conn.ssl_sock.getpeername())
        print conn.ssl_sock.cipher()
    else:
        print 'Not connected...'

def connect(conn, ipaddr):
    conn.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    conn.ssl_sock = ssl.wrap_socket(conn.sock,
                           server_side=False,
                           ca_certs="/etc/dnds/cert-demo/dsd_cert.pem",
                           certfile="/etc/dnds/cert-demo/dnd_cert.pem",
                           keyfile="/etc/dnds/cert-demo/dnd_privkey.pem",
                           ssl_version=ssl.PROTOCOL_TLSv1)

    conn.ssl_sock.connect((ipaddr, 9091))
    conn.connected = True
    print 'Connected!'

def disconnect(conn):
    conn.ssl_sock.shutdown(socket.SHUT_RDWR)
    conn.ssl_sock.close()
    conn.connected = False
    print 'disconnect!'

def main():
    signal.signal(signal.SIGINT, signal_handler)
    loop()

def loop():

    conn = Connection()

    while True:
        line_input = raw_input('dsctl> ')
        command, sep, arg = line_input.partition(' ')

        if command == 'exit':
            sys.exit(0)

        if command == 'connect':
            connect(conn, arg)

        if command == 'disconnect':
            disconnect(conn)

        if command == 'status':
            status(conn)

        if command == 'help':
            dsctl_help()

if __name__ == '__main__':
    main()
