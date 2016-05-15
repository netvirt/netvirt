#ifndef __SERVICE_MAIN_H__
#define __SERVICE_MAIN_H__

#include <jni.h>

#include <QThread>

class QHostAddress;

#ifdef __cplusplus
extern "C" {
#endif

    JNIEXPORT void JNICALL Java_com_netvirt_netvirt_ToyVpnServiceQt_main(JNIEnv *,
                                                                         jobject,
                                                                         jobject,
                                                                         jstring,
                                                                         jint,
                                                                         jstring);

#ifdef __cplusplus
}
#endif

bool protect(int socket);
int configure(int mtu,
              const QString &address,
              int address_mask,
              const QString &route,
              int route_mask,
              const QString &dns_server,
              const QString &search_domain,
              const QHostAddress &server);

class MainThread: public QThread {
    Q_OBJECT
    public:
        MainThread(const QString &server_host,
                     int server_port,
                     const QString &secret);
        void run() Q_DECL_OVERRIDE;
    private:
        QString server_host;
        int server_port;
        QString secret;
};

#endif
