#ifndef __AGENT_H__
#define __AGENT_H__

#include <QObject>
#include <QUdpSocket>

class NetvirtAgent : public QObject {
        Q_OBJECT

    public:
        NetvirtAgent();

    public slots:
        void connect_(const QString &host, const QString &port, const QString &secret);
        void disconnect_();

    signals:
        void connected();
        void disconnected();
};

#endif
