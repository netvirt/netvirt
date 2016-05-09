#ifndef __SERVICE_H__
#define __SERVICE_H__

#include <QHostAddress>
#include <QObject>

class QUdpSocket;

class VPNService : public QObject {
    Q_OBJECT

    public:
        VPNService(const QString& server_host, int server_port, const QString& secret);
        void initialize();
    private slots:
        void testSlot();
    signals:
        void testSignal();
    private:
        QUdpSocket *server;
        QHostAddress server_host;
        quint16 server_port;
        QString secret;
};

#endif
