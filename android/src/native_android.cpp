#include <android/log.h>
#include <jni.h>

#include <QtAndroidExtras/QAndroidJniObject>
#include <QHostAddress>

#include "service_main.h"

#define LOG_TAG "ToyVpnService"

static QAndroidJniObject toyVpnServiceJava;

void start_service(const QString &host, const QString &port, const QString &secret) {
    QAndroidJniObject::callStaticMethod<void>(
        "com/netvirt/netvirt/NetvirtAgent",
        "connect",
        "(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V",
        QAndroidJniObject::fromString(host).object<jstring>(),
        QAndroidJniObject::fromString(port).object<jstring>(),
        QAndroidJniObject::fromString(secret).object<jstring>()
    );
}

extern "C" {
JNIEXPORT void JNICALL Java_com_netvirt_netvirt_ToyVpnServiceQt_main(JNIEnv *env,
                                                                     jobject thisObj,
                                                                     jobject toyVpnServiceJava_,
                                                                     jstring server_host_,
                                                                     jint server_port_,
                                                                     jstring secret_) {
    Q_UNUSED(env);
    Q_UNUSED(thisObj);
    __android_log_write(ANDROID_LOG_INFO, "ToyVpnService", "beginning of main()");

    toyVpnServiceJava = QAndroidJniObject(toyVpnServiceJava_);
    QString server_host = QAndroidJniObject(server_host_).toString();
    int server_port = server_port_;
    QString secret = QAndroidJniObject(secret_).toString();

    MainThread *service_thread = new MainThread(server_host, server_port, secret);
    service_thread->start();

    __android_log_write(ANDROID_LOG_INFO, "ToyVpnService", "ending of main()");
}
}

bool protect(int socket) {
    __android_log_write(ANDROID_LOG_INFO, "ToyVpnService", "protecting socket " + QString::number(socket).toUtf8());
    return (bool) toyVpnServiceJava.callMethod<jboolean>("protect", "(I)Z", socket);
}

int configure(int mtu,
              const QString &address,
              int address_mask,
              const QString &route,
              int route_mask,
              const QString &dns_server,
              const QString &search_domain,
              const QString &server)
{
    return toyVpnServiceJava.callMethod<int>("configure_",
                                             "(ILjava/lang/String;ILjava/lang/String;ILjava/lang/String;Ljava/lang/String;Ljava/lang/String;)I",
                                             mtu,
                                             QAndroidJniObject::fromString(address).object<jstring>(),
                                             address_mask,
                                             QAndroidJniObject::fromString(route).object<jstring>(),
                                             route_mask,
                                             QAndroidJniObject::fromString(dns_server).object<jstring>(),
                                             QAndroidJniObject::fromString(search_domain).object<jstring>(),
                                             QAndroidJniObject::fromString(server).object<jstring>());
}

void log_info(const char *string) {
    __android_log_write(ANDROID_LOG_INFO, LOG_TAG, string);
}

void log_info(const QByteArray &string) {
    log_info(string.data());
}

void log_info(const QString &string) {
    log_info(string.toUtf8());
}
