#ifndef __AGENT_H__
#define __AGENT_H__

#include <QObject>
#include <QUdpSocket>

#include "config.h"

class NetvirtAgent : public QObject {
        Q_OBJECT

    public:
        NetvirtAgent();
        ~NetvirtAgent();

    public slots:
        void initialize();
        void provision(const QString &provisioning_key);
        void connect_(const QString &host, const QString &port, const QString &secret);
        void disconnect_();

    signals:
        void provisioned();
        void connected();
        void disconnected();

    protected:
        Config *_config;
};

#endif
