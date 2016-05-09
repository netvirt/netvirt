#ifndef __SERVICE_MAIN_H__
#define __SERVICE_MAIN_H__

#include <jni.h>
#include <QThread>

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
