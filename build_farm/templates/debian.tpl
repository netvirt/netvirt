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

{% block build_nvagent %}
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
    build_nvagent_gui
}
{% endblock %}
