#include <android/log.h>
#include <jni.h>
#include <QtAndroidExtras/QAndroidJniObject>
#include <QThread>

#include "service.h"
#include "service_main.h"

static QAndroidJniObject toyVpnServiceJava;

JNIEXPORT void JNICALL Java_com_netvirt_netvirt_ToyVpnServiceQt_main(JNIEnv *env,
                                                                     jobject thisObj,
                                                                     jobject toyVpnServiceJava_,
                                                                     jstring server_host_,
                                                                     jint server_port_,
                                                                     jstring secret_) {
    __android_log_write(ANDROID_LOG_INFO, "ToyVpnService", "beginning of main()");

    toyVpnServiceJava = QAndroidJniObject(toyVpnServiceJava_);
    QString server_host = QAndroidJniObject(server_host_).toString();
    int server_port = server_port_;
    QString secret = QAndroidJniObject(secret_).toString();

    MainThread *service_thread = new MainThread(server_host, server_port, secret);
    service_thread->start();

    __android_log_write(ANDROID_LOG_INFO, "ToyVpnService", "ending of main()");
}

bool protect(int socket) {
    return (bool) toyVpnServiceJava.callMethod<jboolean>("protect", "(I)Z", socket);
}


MainThread::MainThread(const QString &server_host,
                           int server_port,
                           const QString &secret)
    : server_host(server_host),
      server_port(server_port),
      secret(secret)
{
}

void MainThread::run() {
    VPNService *service = new VPNService(this->server_host, this->server_port, this->secret);
    service->initialize();
    QThread::run();
}
