#ifndef __AGENT_H__
#define __AGENT_H__

#include <QObject>
#include <QByteArray>
#include <QNetworkReply>
#include <QUdpSocket>

#include "config.h"

class QNetworkReply;

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
        void provisioningFinished();
        void provisioningError(QNetworkReply::NetworkError error);

    signals:
        void provisioned();
        void connected();
        void disconnected();

    protected:
        Config *_config;
        QNetworkReply *_provisioning_reply;

    private:
        bool gen_X509Req(QByteArray &csr_text, QByteArray &private_key_text);
};

#endif
