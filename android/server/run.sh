#!/bin/sh

echo "adding iptables rules"
sudo iptables -t nat -D POSTROUTING -s 10.0.0.0/8 -o eth0 -j MASQUERADE
sudo iptables -t nat -A POSTROUTING -s 10.0.0.0/8 -o eth0 -j MASQUERADE
echo "adding tun0"
sudo ip tuntap del dev tun0 mode tun
sudo ip tuntap add dev tun0 mode tun
echo "configuring tun0"
sudo ifconfig tun0 10.0.0.1 dstaddr 10.0.0.2 up
echo "running server tun0"
./ToyVpnServer tun0 8000 test -m 1400 -a 10.0.0.2 32 -d 10.0.0.1 -r 0.0.0.0 0
