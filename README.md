What is NetVirt?
----------------
NetVirt is a network virtualization platform (NVP).

NetVirt is well suited to create a Network as a service (NaaS) that
provides multi-tenant L2 network.

Cloud networks are similar to a virtual private network (VPN) because
they enable users to securely access files, printers, applications, etc.
from anywhere in the world, on any device. However, cloud networks are
multi-tenant private virtual cloud networks that overlay the Internet.
Each virtual cloud network functions like a borderless LAN and provides
fully switched, any-to-any connectivity between servers, PCs, and mobile
devices from anywhere. -- https://en.wikipedia.org/wiki/Cloud-based_networking

## nvagent

### Local Development + Testing: MacOSx

1. `git clone` repo locally.
2. `brew install scons cmake libevent curl jansson`
3. `git submodule init`
4. `git submodule update`
5. `cd tapcfg`
6. `./buildall.sh`
7. `mkdir build` from the main directory.
8. `cd build`, then `cmake`, then `make`.
9. In the `/nvagent/src/netvirt-agent2.app/Contents/MacOS` directory, you will find the agent binary for MacOS.
10. `$ sudo ./netvirt-agent2 -k <provisioning-key>`
11. `$ sudo ./netvirt-agent2 -l <node-name>`
11. `$ sudo ./netvirt-agent2 -c <node-name>`
12. If you head to the dashboard on the site, you should see the node connected to your network!

### TODO(sneha) Local Development + Testing: Ubuntu
