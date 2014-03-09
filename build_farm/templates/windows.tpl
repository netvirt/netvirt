{% extends "base.tpl" %}

{% set libconfig_dir_name = "libconfig-win32" %}
{% set tapcfg_dir_name = "tapcfg-win32" %}

{% block global_variables %}
openssl_dir="/data/dnds/openssl"
openssl_root="$openssl_dir/mingw32"
wine_dir="/data/dnds/wine"
qt_root="$wine_dir/drive_c/Qt/4.8.5"
pthreads_dir="/data/dnds/pthreads"
{% endblock %}

{% block install_build_dependencies %}
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

{% block build_dnc %}
function build_dnc () {
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
{% endblock %}
