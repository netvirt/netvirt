#ifndef __AGENT_H__
#define __AGENT_H__

#include <QObject>
#include <QUdpSocket>

class NetvirtAgent : public QObject {
        Q_OBJECT

    public:
        NetvirtAgent();

    public slots:
        void connect_();
        void disconnect_();

    private slots:
        void processServerData();

    signals:
        void connected();
        void disconnected();
        void messageReceived(const QString &message);

    private:
        void server2client(QByteArray payload);
        void client2server(QByteArray payload);

        QUdpSocket *server;
};

#endif
