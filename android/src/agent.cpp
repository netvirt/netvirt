#include <QtAndroidExtras/QAndroidJniObject>

#include "agent.h"
#include "logging.h"

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
    QAndroidJniObject::callStaticMethod<void>(
        "com/netvirt/netvirt/NetvirtAgent",
        "connect",
        "(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V",
        QAndroidJniObject::fromString(host).object<jstring>(),
        QAndroidJniObject::fromString(port).object<jstring>(),
        QAndroidJniObject::fromString(secret).object<jstring>()
    );
    emit connected();
}

void NetvirtAgent::disconnect_() {
    emit disconnected();
}
