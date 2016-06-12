#ifndef __SERVICE_MAIN_H__
#define __SERVICE_MAIN_H__

#include <QThread>

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
