#include <QtAndroidExtras/QAndroidJniObject>

#include "agent.h"

NetvirtAgent::NetvirtAgent()
{
}

void NetvirtAgent::provision(const QString &provisioning_key) {
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
