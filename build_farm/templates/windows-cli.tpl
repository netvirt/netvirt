{% extends "base.tpl" %}

{% set libconfig_dir_name = "libconfig-win32" %}
{% set tapcfg_dir_name = "tapcfg-win32" %}

{% block global_variables %}
openssl_dir="/data/netvirt/openssl"
openssl_root="$openssl_dir/mingw32"
pthreads_dir="/data/netvirt/pthreads"
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
    apt-get install -y git scons cmake build-essential mingw-w64 nsis
    [ -d "$openssl_dir" ] || install_openssl
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
    build_dir="$PWD/build.windows.cli"
    mcd "$build_dir"
    rm -rf *
    set -e
    cmake -DCMAKE_TOOLCHAIN_FILE=win32/toolchain-mingw32.cmake \
          -DOPENSSL_ROOT_DIR="$openssl_dir/mingw32" \
          -DCROSS_COMPILER="i686-w64-mingw32" \
          -DCMAKE_FIND_ROOT_PATH="$qt_root" \
          -DWITH_GUI="no" \
          ..
    make netvirt-agent
    makensis -DOPENSSL_PATH="$openssl_dir/mingw32/lib" \
             -DUDT4_PATH="../udt4" \
             -DLIBCONFIG_PATH="../libconfig" \
             -DTAPCFG_PATH="../tapcfg" \
             -DBDIR="$build_dir" \
             ../win32/package_win32_cli.nsi
    rsync *.exe "$release_dir"
    set +e
    popd
}
{% endblock %}
