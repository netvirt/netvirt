{% extends "base.tpl" %}

{% set libconfig_dir_name = "libconfig-macos" %}
{% set tapcfg_dir_name = "tapcfg-macos" %}

{% block install_build_dependencies %}
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
{% endblock %}

{% block build_udt4 %}
    [ -f src/libudt.dylib ] || make os=OS_X arch=AMD64
{% endblock %}

{% block build_libconfig %}
    [ ! -f Makefile ] && ./configure
    [ -d lib/.libs ] || make -s
{% endblock %}

{% block build_tapcfg %}
    [ -d build ] || scons
{% endblock %}

{% block build_dnc %}
function build_dnc () {
    build_dir=build.mac.gui
    mcd "$build_dir"
    rm -rf *
    cmake ..
    make dnc
    make package
    rsync *.dmg "$release_dir"
    popd
}
{% endblock %}
