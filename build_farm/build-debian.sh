#!/usr/bin/env bash

set -x

release_dir="$1"


function install_build_dependencies() {
    apt-get install -y git scons cmake build-essential libqt4-dev libssl-dev
}

function mcd () {
    mkdir -p "$1" && pushd "$1"
}

function clone_or_pull () {
     if [ -d "$2" ] ; then
         pushd "$2"
         git pull
         popd
     else
         git clone "$1" "$2"
     fi
}

function submodule () {
    [ ! -d "$2" ] && git submodule add "$1" "$2"
}

function clone_dependencies () {
    clone_or_pull https://github.com/nicboul/DNDS.git DNDS
    cd DNDS
    clone_or_pull https://github.com/nicboul/udt4.git udt4
    clone_or_pull https://github.com/nicboul/libconfig.git libconfig-linux
    clone_or_pull https://github.com/nicboul/tapcfg.git tapcfg-linux
}

function fix_libconfig_git () {
    # git creates files in alphabetic order, messing with dependency detection
    # of make. Specifically, *.y files are created after *.c files, which are
    # generated from *.y files
    touch lib/*.c
}

function build_dependencies () {
    pushd udt4
    make
    popd

    pushd libconfig-linux
    fix_libconfig_git
    [ ! -f Makefile ] && ./configure
    make
    popd

    pushd tapcfg-linux
    ./buildall.sh
    popd
}

function build_dnc_cli () {
    mcd build.linux.cli
    rm -rf *
    cmake .. -DWITH_GUI=OFF
    make dnc
    make package
    rsync *.deb "$release_dir"
    popd
}

function build_dnc_gui () {
    mcd build.linux.gui
    rm -rf *
    cmake ..
    make dnc
    make package
    rsync *.deb "$release_dir"
    popd
}

function build_dnc () {
    build_dnc_cli
    build_dnc_gui
}

install_build_dependencies
clone_dependencies
build_dependencies
build_dnc
