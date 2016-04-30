#!/bin/sh

sudo iptables -t nat -A POSTROUTING -s 10.0.0.0/8 -o eth0 -j MASQUERADE
sudo ip tuntap add dev tun0 mode tun
sudo ifconfig tun0 10.0.0.1 dstaddr 10.0.0.2 up
./ToyVpnServer tun0 8000 test -m 1400 -a 10.0.0.2 32 -d 10.0.0.1 -r 0.0.0.0 0
