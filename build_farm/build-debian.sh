#!/usr/bin/env bash

set -x

release_dir="$1"


function install_build_dependencies() {
    apt-get install -y git scons cmake build-essential libevent-dev libssl-dev
}

function mcd () {
    mkdir -p "$1" && pushd "$1"
}

function clone_or_pull () {
     if [ -d "$2" ] ; then
         pushd "$2"
         git pull || exit 1
         popd
     else
         git clone -b proto1.2 "$1" "$2" || exit 1
     fi
}

function submodule () {
    [ ! -d "$2" ] && git submodule add "$1" "$2"
}

function clone_dependencies () {
    set -e
    clone_or_pull https://github.com/netvirt/netvirt.git netvirt
    cd netvirt
    git submodule init
    git submodule update
    set +e
}

function fix_libconfig_git () {
    # git creates files in alphabetic order, messing with dependency detection
    # of make. Specifically, *.y files are created after *.c files, which are
    # generated from *.y files
    touch lib/*.c
}

function build_dependencies () {
    pushd tapcfg
    ./buildall.sh
    popd
}

function build_nvagent_cli () {
    mcd build.linux.cli
    rm -rf *
    set -e
    cmake .. -DWITH_GUI=OFF
    make nvagent
    make package
    rsync *.deb "$release_dir"
    set +e
    popd
}

function build_nvagent_gui () {
    mcd build.linux.gui
    rm -rf *
    set -e
    cmake ..
    make nvagent
    make package
    rsync *.deb "$release_dir"
    set +e
    popd
}

function build_nvagent () {
    build_nvagent_cli
#    build_nvagent_gui
}

install_build_dependencies
clone_dependencies
build_dependencies
build_nvagent
