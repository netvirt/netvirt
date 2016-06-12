#!/bin/sh

echo "adding tun0"
sudo ip tuntap del dev tun0 mode tun
sudo ip tuntap add dev tun0 mode tun
echo "configuring tun0"
sudo ip address add 10.0.0.1 peer 10.0.0.2 dev tun0
sudo ip link set tun0 up
echo "running server tun0"
./ToyVpnServer tun0 8000 test -m 1400 -a 10.0.0.2 32 -d 10.0.0.1 -r 0.0.0.0 0
exit 0

# For Docker:
mkdir -p /dev/net
mknod /dev/net/tun c 10 200
ip tuntap add dev tun0 mode tun
ip address add 10.0.0.1 peer 10.0.0.2 dev tun0
ip link set tun0 up
