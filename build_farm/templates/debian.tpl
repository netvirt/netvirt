{% extends "base.tpl" %}

{% set libconfig_dir_name = "libconfig-linux" %}
{% set tapcfg_dir_name = "tapcfg-linux" %}

{% block install_build_dependencies %}
function install_build_dependencies() {
    apt-get install -y git scons cmake build-essential libqt4-dev libssl-dev
}
{% endblock %}

{% block build_udt4 %}
    make
{% endblock %}

{% block build_libconfig %}
    [ ! -f Makefile ] && ./configure
    make
{% endblock %}

{% block build_tapcfg %}
    ./buildall.sh
{% endblock %}

{% block build_dnc %}
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
{% endblock %}
