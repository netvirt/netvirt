#include "agent.h"
#include "logging.h"
#include "native.h"

NetvirtAgent::NetvirtAgent()
    : _config(new Config())
{
}

NetvirtAgent::~NetvirtAgent() {
    delete this->_config;
}

void NetvirtAgent::initialize() {
    if (this->_config->isProvisioned()) {
        log_info("NetvirtAgent is provisioned");
        emit provisioned();
    }
}

void NetvirtAgent::provision(const QString &provisioning_key) {
    this->_config->provision();
    emit provisioned();
}

void NetvirtAgent::connect_(const QString &host, const QString &port, const QString &secret) {
    start_service(host, port, secret);
    emit connected();
}

void NetvirtAgent::disconnect_() {
    emit disconnected();
}
