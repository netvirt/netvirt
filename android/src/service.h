#ifndef __SERVICE_H__
#define __SERVICE_H__

#include <QFile>
#include <QObject>
#include <QTimer>

class QUdpSocket;

class VPNService : public QObject {
    Q_OBJECT

    public:
        VPNService(const QString &server_host, int server_port, const QString &secret);
        void initialize();
    private slots:
        void testSlot();
        void handshakeReceived();
        void serverToClient();
        void clientToServer();
        void pingServer();
    signals:
        void testSignal();
    private:
        void handshake();
        int configureInterface(const QString &parameters);

        QUdpSocket *server;
        QString server_host;
        quint16 server_port;
        QString secret;
        QFile *client;
        QTimer *ping_timer;
};

#endif
