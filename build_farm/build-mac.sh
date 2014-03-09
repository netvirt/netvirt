#!/usr/bin/env bash

set -x

release_dir="$1"

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

port_dependencies="scons cmake qt4-mac"

function dependencies_are_installed() {
    for dependency in $port_dependencies ; do
        if [ $(port list installed and name:$dependency | wc -l) -eq 0 ] ; then
            return 1
        fi
    done
    return 0
}

function install_build_dependencies() {
    if ! dependencies_are_installed ; then
        sudo port install $port_dependencies
    fi
}
install_build_dependencies

function clone_dependencies () {
    clone_or_pull https://github.com/nicboul/DNDS.git DNDS
    cd DNDS
    submodule https://github.com/nicboul/udt4.git udt4
    submodule https://github.com/nicboul/libconfig.git libconfig-macos
    submodule https://github.com/nicboul/tapcfg.git tapcfg-macos
    git submodule update --init
}
clone_dependencies

function fix_libconfig_git () {
    # git creates files in alphabetic order, messing with dependency detection
    # of make. Specifically, *.y files are created after *.c files, which are
    # generated from *.y files
    touch lib/*.c
}

function build_dependencies () {
    pushd udt4
    [ -f src/libudt.dylib ] || make os=OS_X arch=AMD64
    popd

    pushd libconfig-macos
    fix_libconfig_git
    [ ! -f Makefile ] && ./configure
    [ -d lib/.libs ] || make -s
    popd

    pushd tapcfg-macos
    [ -d build ] || scons
    popd
}
build_dependencies

function build_dnc_gui () {
    build_dir=build.mac.gui
    mcd "$build_dir"
    rm -rf *
    cmake ..
    make dnc
    make package
    rsync *.dmg "$release_dir"
    popd
}
build_dnc_gui
