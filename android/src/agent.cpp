#include <QJsonDocument>
#include <QNetworkRequest>
#include <QNetworkAccessManager>
#include <QUrl>

#include "agent.h"
#include "logging.h"
#include "native.h"

NetvirtAgent::NetvirtAgent()
    : _config(new Config())
{
}

NetvirtAgent::~NetvirtAgent() {
    delete this->_config;
}

void NetvirtAgent::initialize() {
    if (this->_config->isProvisioned()) {
        log_info("NetvirtAgent is provisioned");
        emit provisioned();
    }
}

void NetvirtAgent::provision(const QString &provisioning_key) {
    QUrl url;
    url.setScheme("http");
    url.setHost(this->_config->controllerHost());
    url.setPort(this->_config->controllerPort());
    url.setPath("/1.0/provisioning");

    QNetworkRequest request = QNetworkRequest(url);
    request.setHeader(QNetworkRequest::ContentTypeHeader, "application/json");
    request.setRawHeader("Accept", "application/json");

    QVariantMap body;
    body["provisioning_key"] = provisioning_key;
    body["csr"] = "-----BEGIN CERTIFICATE REQUEST-----\nabcdef...\n-----END CERTIFICATE REQUEST-----";
    body["client_version"] = "0.6";
    QByteArray raw_body = QJsonDocument::fromVariant(body).toJson();

    qDebug() << "Sending provisioning request to" << url.toString();
    qDebug() << "With body" << raw_body;

    QNetworkAccessManager *http = new QNetworkAccessManager(this);
    this->_provisioning_reply = http->post(request, raw_body);
    connect(this->_provisioning_reply, SIGNAL(finished()),
            this, SLOT(provisioningFinished()));
    connect(this->_provisioning_reply, SIGNAL(error(QNetworkReply::NetworkError)),
            this, SLOT(provisioningError(QNetworkReply::NetworkError)));
}

void NetvirtAgent::provisioningFinished()
{
    qDebug() << Q_FUNC_INFO;

    this->_config->provision();

    emit provisioned();
}

void NetvirtAgent::provisioningError(QNetworkReply::NetworkError error)
{
    qDebug() << Q_FUNC_INFO;
    qDebug() << error;
}

void NetvirtAgent::connect_(const QString &host, const QString &port, const QString &secret) {
    start_service(host, port, secret);
    emit connected();
}

void NetvirtAgent::disconnect_() {
    emit disconnected();
}
