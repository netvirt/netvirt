{% extends "base.tpl" %}

{% set libconfig_dir_name = "libconfig-win32" %}
{% set tapcfg_dir_name = "tapcfg-win32" %}

{% block global_variables %}
libressl_version="2.5.0"
libressl_dir="/data/netvirt/"
libressl_pathname=libressl-${libressl_version}-windows
wine_dir="/data/netvirt/wine"
qt_root="$wine_dir/drive_c/Qt/4.8.4"
pthreads_dir="/data/netvirt/pthreads"
{% endblock %}

{% block install_build_dependencies %}
function install_libressl () {
    libressl_archive="/tmp/libressl.zip"
    libressl_url="https://ftp.openbsd.org/pub/OpenBSD/LibreSSL/libressl-${libressl_version}-windows.zip"
    [ -r "$libressl_archive" ] || curl -o "$libressl_archive" "$libressl_url"
    mkdir -p "$libressl_dir"
    unzip "$libressl_archive" -d "$libressl_dir"
}

function install_qt () {
    qt_installer="/tmp/qt-win32-installer"
    qt_url="http://download.qt-project.org/official_releases/qt/4.8/4.8.4/qt-win-opensource-4.8.4-mingw.exe"
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
    cp "$pthreads_dir"/include/* "$libressl_dir/$libressl_pathname/include"
}

function install_build_dependencies() {
    apt-get install -y git scons cmake build-essential libqt4-dev mingw-w64 nsis wine
    [ -d "$libressl_dir/$libressl_pathname" ] || install_libressl
    [ -d "$wine_dir" ] || install_qt
    [ -d "$pthreads_dir" ] || install_pthreads_win32
}
{% endblock %}

{% block build_udt4 %}
    [ -f src/libudt.dll ] || make CXX='i686-w64-mingw32-g++' os=WIN32 -s
{% endblock %}

{% block build_libconfig %}
    [ -f Makefile ] || ./configure --host=i686-w64-mingw32
    [ -d lib/.libs ] || make -s
{% endblock %}

{% block build_tapcfg %}
    [ -d build ] || scons --force-mingw32
{% endblock %}

{% block build_nvagent %}
function build_nvagent () {
    build_dir="$PWD/build.windows.gui"
    mcd "$build_dir"
    rm -rf *
    set -e
    cmake -DCMAKE_TOOLCHAIN_FILE=win32/toolchain-mingw32.cmake \
          -DLIBRESSL_ROOT_DIR="$libressl_dir/$libressl_pathname" \
          -DCROSS_COMPILER="i686-w64-mingw32" \
          -DCMAKE_FIND_ROOT_PATH="$qt_root" \
          ..
    make netvirt-agent
    makensis -DLIBRESSL_PATH="$libressl_dir/$libressl_pathname/x86" \
             -DQT_PATH="$qt_root" \
             -DUDT4_PATH="../udt4" \
             -DLIBCONFIG_PATH="../libconfig" \
             -DTAPCFG_PATH="../tapcfg" \
             -DBDIR="$build_dir" \
             ../win32/package_win32.nsi
    rsync *.exe "$release_dir"
    set +e
    popd
}
{% endblock %}
