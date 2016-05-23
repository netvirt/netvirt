#ifndef __AGENT_H__
#define __AGENT_H__

#include <QObject>
#include <QUdpSocket>

class NetvirtAgent : public QObject {
        Q_OBJECT

    public:
        NetvirtAgent();

    public slots:
        void provision(const QString &provisioning_key);
        void connect_(const QString &host, const QString &port, const QString &secret);
        void disconnect_();

    signals:
        void provisioned();
        void connected();
        void disconnected();
};

#endif
