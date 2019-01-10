# build-*

## What these scripts are for

These scripts are used to compile the NetVirt Agent from a pristine Debian machine.

Copy the script you want on the fresh Debian and run it. It will download
everything that is needed to compile the DynVPN client, install it, compile the
client and create the package, ready to be installed.

## Prerequisites

The scripts must be run with administrative rights, in order to install build
dependencies.


# Dockerfile-windows-cli

This Dockerfile builds the netvirt-agent for Windows 32 bits.

To build the builder:

  docker build -t netvirt/netvirt-agent-builder-windows-cli -f build_farm/Dockerfile-windows-cli .

To build the agent:

  NETVIRT_ROOT_DIR=/path/to/netvirt docker run -it --cidfile=/tmp/netvirt-agent-builder.cid -v $NETVIRT_ROOT_DIR:/usr/src/netvirt:ro netvirt/netvirt-agent-builder-windows-cli

  docker cp $(cat /tmp/netvirt-agent-builder.cid):/tmp/netvirt-agent2-cli_x86.exe /tmp/netvirt-agent2-cli_x86.exe
