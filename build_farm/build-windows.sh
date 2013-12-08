#!/usr/bin/env bash

set -x

release_dir="$1"
openssl_dir="/data/dnds/openssl"
openssl_root="$openssl_dir/mingw32"
wine_dir="/data/dnds/wine"
qt_root="$wine_dir/drive_c/Qt/4.8.5"
pthreads_dir="/data/dnds/pthreads"

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

function install_openssl () {
    openssl_archive="/tmp/openssl-mingw32.tar.gz"
    openssl_url="http://www.blogcompiler.com/wp-content/uploads/2011/12/openssl-1.0.0e-mingw32.tar.gz"
    [ -r "$openssl_archive" ] || wget "$openssl_url" -O "$openssl_archive"
    mkdir -p "$openssl_dir"
    tar -C "$openssl_dir" -xzf "$openssl_archive"
    cp "$openssl_root"/bin/{ssl,lib}eay32.dll "$openssl_root/lib"
}

function install_qt () {
    qt_installer="/tmp/qt-win32-installer"
    qt_url="http://download.qt-project.org/official_releases/qt/4.8/4.8.5/qt-win-opensource-4.8.5-mingw.exe"
    [ -r "$qt_installer" ] || wget "$qt_url" -O "$qt_installer"
    mkdir -p "$wine_dir"
    WINEPREFIX="$wine_dir" wine "$qt_installer" /S
}

function install_pthreads_win32 () {
    pthreads_archive="/tmp/pthreads.zip"
    pthreads_url="ftp://sourceware.org/pub/pthreads-win32/pthreads-w32-2-9-1-release.zip"
    [ -r "$pthreads_archive" ] || wget "$pthreads_url" -O "$pthreads_archive"
    unzip "$pthreads_archive" 'Pre-built.2/*' -d /tmp
    mv "/tmp/Pre-built.2" "$pthreads_dir"
    cp "$pthreads_dir/lib/x86/libpthreadGC2.a" "/usr/i686-w64-mingw32/lib"
    ln -f "/usr/i686-w64-mingw32/lib/"libpthread{GC2,}.a
    cp "$pthreads_dir/dll/x86/pthreadGC2.dll" "/usr/i686-w64-mingw32/lib"
    ln -f "/usr/i686-w64-mingw32/lib/"pthread{GC2,}.dll
    cp "$pthreads_dir"/include/* "$openssl_root/include"
}

function install_build_dependencies() {
    apt-get install -y git scons cmake build-essential libqt4-dev mingw-w64 nsis wine
    [ -d "$openssl_dir" ] || install_openssl
    [ -d "$wine_dir" ] || install_qt
    [ -d "$pthreads_dir" ] || install_pthreads_win32
}

function clone_dependencies () {
    clone_or_pull https://github.com/nicboul/DNDS.git DNDS
    cd DNDS
    submodule https://github.com/nicboul/udt4.git udt4
    submodule https://github.com/nicboul/libconfig.git libconfig-win32
    submodule https://github.com/nicboul/tapcfg.git tapcfg-win32
    git submodule update --init
}

function fix_libconfig_git () {
    # git creates files in alphabetic order, messing with dependency detection
    # of make. Specifically, *.y files are created after *.c files, which are
    # generated from *.y files
    touch lib/*.c
}

function build_dependencies () {
    pushd udt4
    [ -f src/libudt.dll ] || make CXX='i686-w64-mingw32-g++' os=WIN32 -s
    popd

    pushd libconfig-win32
    fix_libconfig_git
    [ -f Makefile ] || ./configure --host=i686-w64-mingw32
    [ -d lib/.libs ] || make -s
    popd

    pushd tapcfg-win32
    [ -d build ] || scons --force-mingw32
    popd
}

function build_dnc_gui () {
    build_dir=build.windows.gui
    mcd "$build_dir"
    rm -rf *
    cmake -DCMAKE_TOOLCHAIN_FILE=./toolchain-mingw32.cmake \
          -DOPENSSL_ROOT_DIR="$openssl_dir/mingw32" \
          -DCROSS_COMPILER="i686-w64-mingw32" \
          -DCMAKE_FIND_ROOT_PATH="$qt_root" \
          ..
    make dnc
    makensis -DOPENSSL_PATH="$openssl_dir/mingw32/lib" \
             -DQT_PATH="$qt_root/bin" \
             -DBDIR="$build_dir" \
             ../package_win32.nsi
    rsync *.exe "$release_dir"
    popd
}

install_build_dependencies
clone_dependencies
build_dependencies
build_dnc_gui
